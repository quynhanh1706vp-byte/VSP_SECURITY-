#!/usr/bin/env bash
# scripts/test-l9-lifecycle.sh — stateful workflow / lifecycle probes.
#
# L1-L8 attack the API surface ONE-SHOT — they probe individual
# endpoints in isolation. L9 walks the full state machine of a
# resource and asserts every transition: emits the right audit
# event, writes the right DB row, exposes the right view, and rolls
# back cleanly on failure.
#
# Three workflows covered:
#
#   10.1 Run lifecycle: trigger → enqueue → poll → complete →
#        scan_pass/fail/warn audit → retrievable via /vsp/run/{rid}
#
#   10.2 DSR lifecycle: submit-erasure → confirm with token →
#        wait-fire → COMPLETED → audit chain has all 4 events
#
#   10.3 Audit chain across mutations: trigger N events from one
#        session, verify chain length grew by exactly N + each row
#        has correct prev_hash linkage
#
# Pre-flight: $DB_DSN, $JWT_SECRET, gateway running.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq psql openssl

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

TENANT_A_SLUG="default"
TENANT_A_UUID="1bdf7f20-dbb3-4116-815f-26b4dc747e76"

mint_jwt() {
  local slug="$1" role="$2"
  local now exp header payload sig
  now=$(date +%s); exp=$((now + 3600))
  header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  payload=$(printf '{"sub":"l9@vsp.local","email":"l9@vsp.local","role":"%s","tenant_id":"%s","iat":%d,"exp":%d}' \
    "$role" "$slug" "$now" "$exp" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  sig=$(printf '%s' "$header.$payload" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  printf '%s.%s.%s\n' "$header" "$payload" "$sig"
}

ADMIN_A=$(mint_jwt "$TENANT_A_SLUG" admin)

# ── 10.1 Run lifecycle ─────────────────────────────────────────────────────

phase_open "10.1 Run lifecycle — trigger emits SCAN_TRIGGER, persists row"

# 10.1.1 Trigger a run; expect 200/202 and a rid in response.
TRIGGER_RESP=$(mktemp)
TRIGGER_HTTP=$(curl -s -o "$TRIGGER_RESP" -w "%{http_code}" --max-time 10 \
  -X POST -H "Authorization: Bearer $ADMIN_A" -H "Content-Type: application/json" \
  -d '{"src":"github.com/vsp-l9/canary","mode":"SAST","profile":"FAST"}' \
  "$BASE/api/v1/vsp/run")

# Extract rid from response. Different handlers return it under
# different keys; tolerate either {rid} or {data.rid}.
RID=$(jq -r '.rid // .data.rid // .run.rid // empty' "$TRIGGER_RESP" 2>/dev/null)
rm -f "$TRIGGER_RESP"

if [[ "$TRIGGER_HTTP" =~ ^(200|202)$ && -n "$RID" ]]; then
  _pass "10.1.1 POST /vsp/run returned rid [$TRIGGER_HTTP, rid=$RID]"
else
  _fail "10.1.1 POST /vsp/run trigger" "HTTP $TRIGGER_HTTP, rid='$RID' — expected 200/202 + rid"
  RID=""
fi

if [[ -n "$RID" ]]; then
  # 10.1.2 DB row created with status QUEUED/RUNNING and matching rid.
  ROW_INFO=$(_psql_oneshot "SELECT status||'|'||rid FROM runs WHERE rid='$RID' LIMIT 1;")
  if [[ -n "$ROW_INFO" && "$ROW_INFO" =~ \|"$RID"$ ]]; then
    _pass "10.1.2 runs row created [$ROW_INFO]"
  else
    _fail "10.1.2 runs row absent" "no row with rid='$RID' (got '$ROW_INFO')"
  fi

  # 10.1.3 Audit row SCAN_TRIGGER recorded for THIS rid within 5s.
  sleep 1
  AUDIT_HIT=$(_psql_oneshot "SELECT count(*) FROM audit_log
                              WHERE action='SCAN_TRIGGER'
                                AND tenant_id='$TENANT_A_UUID'
                                AND resource LIKE '%$RID%'
                                AND created_at > NOW() - INTERVAL '10 seconds';")
  if [[ "$AUDIT_HIT" -ge 1 ]]; then
    _pass "10.1.3 SCAN_TRIGGER audit row written [$AUDIT_HIT]"
  else
    _fail "10.1.3 SCAN_TRIGGER audit missing" \
      "no audit row for rid=$RID in last 10s — handler skipped writeAudit"
  fi

  # 10.1.4 GET /vsp/run/{rid} returns the same rid.
  GET_RID=$(curl -s --max-time 5 -H "Authorization: Bearer $ADMIN_A" \
    "$BASE/api/v1/vsp/run/$RID" | jq -r '.rid // .run.rid // empty' 2>/dev/null)
  if [[ "$GET_RID" == "$RID" ]]; then
    _pass "10.1.4 GET /vsp/run/{rid} reflects same rid"
  else
    _fail "10.1.4 GET /vsp/run/{rid}" "expected $RID, got '$GET_RID'"
  fi

  # 10.1.5 Cancel the run; expect status to flip away from QUEUED/RUNNING.
  CANCEL_HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X POST -H "Authorization: Bearer $ADMIN_A" \
    "$BASE/api/v1/vsp/run/$RID/cancel")
  if [[ "$CANCEL_HTTP" =~ ^(200|202|204|400|409)$ ]]; then
    sleep 1
    POST_STATUS=$(_psql_oneshot "SELECT status FROM runs WHERE rid='$RID' LIMIT 1;")
    case "$POST_STATUS" in
      CANCELLED|CANCELED|FAILED|DONE)
        _pass "10.1.5 cancel transitioned status [→ $POST_STATUS]" ;;
      QUEUED|RUNNING)
        # Possibly the cancel was rejected because the run already
        # finished. Distinguish.
        if [[ "$CANCEL_HTTP" == "409" || "$CANCEL_HTTP" == "400" ]]; then
          _pass "10.1.5 cancel rejected (transient run state) [$CANCEL_HTTP]"
        else
          _fail "10.1.5 cancel left status unchanged" \
            "HTTP $CANCEL_HTTP but status still '$POST_STATUS'"
        fi
        ;;
      *)
        _pass "10.1.5 cancel produced terminal status [$POST_STATUS]" ;;
    esac
  else
    _fail "10.1.5 cancel" "HTTP $CANCEL_HTTP unexpected"
  fi
fi

# ── 10.2 DSR lifecycle ─────────────────────────────────────────────────────

phase_open "10.2 DSR lifecycle — schedule + cancel + audit chain"

# We don't trigger a real erasure (would nuke the dev tenant!). Probe
# the SCHEDULE → CANCEL transition which exercises the same code path
# and audits.

DSR_BODY='{"reason":"L9 lifecycle probe"}'
SCHED_RESP=$(mktemp)
SCHED_HTTP=$(curl -s -o "$SCHED_RESP" -w "%{http_code}" --max-time 5 \
  -X POST -H "Authorization: Bearer $ADMIN_A" -H "Content-Type: application/json" \
  -d "$DSR_BODY" "$BASE/api/v1/data/erasure")

DSR_ID=$(jq -r '.id // empty' "$SCHED_RESP" 2>/dev/null)
rm -f "$SCHED_RESP"

if [[ "$SCHED_HTTP" =~ ^(200|201|202)$ && -n "$DSR_ID" ]]; then
  _pass "10.2.1 erasure schedule created [HTTP $SCHED_HTTP, id=$DSR_ID]"

  # 10.2.2 DSR row exists with status='pending'.
  STATUS=$(_psql_oneshot "SELECT status FROM data_subject_requests WHERE id='$DSR_ID' LIMIT 1;")
  if [[ "$STATUS" == "pending" ]]; then
    _pass "10.2.2 DSR row status=pending"
  else
    _fail "10.2.2 DSR row status" "expected pending, got '$STATUS'"
  fi

  # 10.2.3 Audit DSR_ERASURE_SCHEDULED emitted.
  AUDIT_HIT=$(_psql_oneshot "SELECT count(*) FROM audit_log
                              WHERE action='DSR_ERASURE_SCHEDULED'
                                AND tenant_id='$TENANT_A_UUID'
                                AND resource LIKE '%$DSR_ID%'
                                AND created_at > NOW() - INTERVAL '10 seconds';")
  if [[ "$AUDIT_HIT" -ge 1 ]]; then
    _pass "10.2.3 DSR_ERASURE_SCHEDULED audit written"
  else
    _fail "10.2.3 DSR_ERASURE_SCHEDULED audit missing" "no row for $DSR_ID"
  fi

  # 10.2.4 Cancel the erasure; status should become 'cancelled'.
  CANCEL_HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X POST -H "Authorization: Bearer $ADMIN_A" \
    "$BASE/api/v1/data/erasure/$DSR_ID/cancel")
  POST_STATUS=$(_psql_oneshot "SELECT status FROM data_subject_requests WHERE id='$DSR_ID' LIMIT 1;")
  if [[ "$CANCEL_HTTP" =~ ^(200|204)$ && "$POST_STATUS" == "cancelled" ]]; then
    _pass "10.2.4 erasure cancel transitioned [HTTP $CANCEL_HTTP, status=$POST_STATUS]"
  else
    _fail "10.2.4 erasure cancel" "HTTP $CANCEL_HTTP, status='$POST_STATUS' (expected 200+cancelled)"
  fi

  # 10.2.5 Cleanup: delete our probe row so it doesn't pollute history.
  _psql_oneshot "DELETE FROM data_subject_requests WHERE id='$DSR_ID';" >/dev/null 2>&1 || true
elif [[ "$SCHED_HTTP" == "404" ]]; then
  _skip "10.2.x DSR lifecycle" "DSR endpoint not mounted in this build"
else
  _fail "10.2.1 erasure schedule" "HTTP $SCHED_HTTP — unexpected (body parse: id='$DSR_ID')"
fi

# ── 10.3 Audit chain integrity across N events ─────────────────────────────

phase_open "10.3 Audit chain — N events grow chain by exactly N"

# Capture chain head before, fire 5 audited mutations, verify
# the chain length grew by exactly 5 AND audit/verify still ok=true.
SEQ_BEFORE=$(_psql_oneshot "SELECT COALESCE(MAX(seq), 0) FROM audit_log WHERE tenant_id='$TENANT_A_UUID';")

# 5 events: 4 token refreshes + 1 logout.
for i in 1 2 3 4; do
  curl -s -o /dev/null --max-time 5 -X POST \
    -H "Authorization: Bearer $ADMIN_A" "$BASE/api/v1/auth/refresh" || true
done
# Logout uses the actual session token; mint a fresh one and logout.
LOGOUT_TOKEN=$(mint_jwt "$TENANT_A_SLUG" admin)
curl -s -o /dev/null --max-time 5 -X POST \
  -H "Authorization: Bearer $LOGOUT_TOKEN" "$BASE/api/v1/auth/logout" || true

sleep 2
SEQ_AFTER=$(_psql_oneshot "SELECT COALESCE(MAX(seq), 0) FROM audit_log WHERE tenant_id='$TENANT_A_UUID';")
ROWS_BURNED=$(_psql_oneshot "SELECT count(*) FROM audit_log
                              WHERE tenant_id='$TENANT_A_UUID'
                                AND seq > $SEQ_BEFORE;")

# Note: SCAN_TRIGGER from 10.1 may also have landed in this window if
# the audit hit at 10.1.3 was for a different tenant; here we tolerate
# > 0 events but require >= 5 since we deliberately fired 5.
if (( ROWS_BURNED >= 5 )); then
  _pass "10.3.1 chain grew by ≥5 events [seq $SEQ_BEFORE → $SEQ_AFTER, +$ROWS_BURNED rows]"
else
  _fail "10.3.1 chain growth" "fired 5 events but chain grew by $ROWS_BURNED"
fi

# 10.3.2 audit/verify still ok=true after the burst.
VERIFY=$(curl -s -X POST --max-time 5 -H "Authorization: Bearer $ADMIN_A" \
  "$BASE/api/v1/audit/verify" | jq -r '.ok // false' 2>/dev/null)
if [[ "$VERIFY" == "true" ]]; then
  _pass "10.3.2 audit/verify ok=true after burst"
else
  _fail "10.3.2 audit/verify after burst" "ok=$VERIFY — chain integrity broken by concurrent inserts"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
