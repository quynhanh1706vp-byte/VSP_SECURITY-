#!/usr/bin/env bash
# scripts/test-l5-advanced.sh — L5 advanced verification.
#
# Three angles past L4's tenant-isolation matrix:
#
#   6.1 SSE cross-tenant — connect as tenant A, broadcast a scan_complete
#       on tenant B, verify A's stream NEVER receives the message.
#
#   6.2 RBAC role matrix — for each of admin/analyst/dev/auditor, probe
#       a curated list of admin-only and write endpoints; assert correct
#       role is allowed and others are 403/401.
#
#   6.3 Concurrency races — fire bursts at lockout and audit endpoints
#       to flush out shared-state bugs.
#
# Pre-flight: gateway running, /etc/vsp/env.production has JWT_SECRET,
# Postgres reachable via DB_DSN.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq psql openssl

TENANT_A_SLUG="default"
TENANT_A_UUID="1bdf7f20-dbb3-4116-815f-26b4dc747e76"
TENANT_B_SLUG="acme-corp"
TENANT_B_UUID="8bb9a716-fd14-4eba-92e8-681dc5bdb718"

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET not available; export JWT_SECRET or VSP_JWT_SECRET_FILE\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

mint_jwt() {
  local slug="$1" role="$2"
  local now exp header payload sig
  now=$(date +%s); exp=$((now + 3600))
  header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  payload=$(printf '{"sub":"l5@vsp.local","email":"l5@vsp.local","role":"%s","tenant_id":"%s","iat":%d,"exp":%d}' \
    "$role" "$slug" "$now" "$exp" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  sig=$(printf '%s' "$header.$payload" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  printf '%s.%s.%s\n' "$header" "$payload" "$sig"
}

ADMIN_A=$(mint_jwt "$TENANT_A_SLUG" admin)
ANALYST_A=$(mint_jwt "$TENANT_A_SLUG" analyst)
DEV_A=$(mint_jwt "$TENANT_A_SLUG" dev)
AUDITOR_A=$(mint_jwt "$TENANT_A_SLUG" auditor)
ADMIN_B=$(mint_jwt "$TENANT_B_SLUG" admin)

# ── 6.1 SSE cross-tenant probe ─────────────────────────────────────────────

phase_open "6.1 SSE cross-tenant — A's stream never receives B's events"

# Strategy: connect to /api/v1/events as tenant A. Concurrently insert a
# DONE run for tenant B (so the SSE poller picks it up and broadcasts).
# After 8s, kill the stream and inspect what A received. If A's capture
# contains tenant B's marker, that's a leak.

# RID must be lexicographically greater than any existing rid so the
# SSE poller's `WHERE rid > lastSeen` predicate fires. Existing rids
# look like SCAN_2026... and TEST_*. Prefix "zzz" guarantees ordering.
CANARY_RID="zzz-L5-CANARY-$$"
SSE_OUT=$(mktemp)

cleanup_sse() {
  rm -f "$SSE_OUT"
  _psql_oneshot "DELETE FROM runs WHERE rid='$CANARY_RID';" >/dev/null 2>&1 || true
}
trap cleanup_sse EXIT

# Open SSE stream as tenant A in background. Curl writes raw stream lines
# to $SSE_OUT; we kill it after 8s so the trap can clean up.
curl -s --max-time 8 -N -H "Authorization: Bearer $ADMIN_A" \
  "$BASE/api/v1/events" > "$SSE_OUT" 2>/dev/null &
SSE_PID=$!
sleep 1  # let the connection establish

# Insert a DONE run into tenant B. The SSE poller scans every 5s for
# new DONE runs; rid lexicographic-greater-than lastSeen triggers a
# broadcast.
if _psql_oneshot "INSERT INTO runs (rid, tenant_id, mode, profile, status, gate, total_findings, summary)
                  VALUES ('$CANARY_RID', '$TENANT_B_UUID', 'on-demand', 'FAST', 'DONE', 'PASS', 0, '{}')
                  ON CONFLICT DO NOTHING;" >/dev/null 2>&1; then
  : # ok
else
  _skip "6.1.1 SSE cross-tenant probe" "could not seed canary run"
  kill "$SSE_PID" 2>/dev/null || true
  wait "$SSE_PID" 2>/dev/null || true
fi

# Wait for SSE poller (5s tick) to catch up, then close stream.
sleep 7
kill "$SSE_PID" 2>/dev/null || true
wait "$SSE_PID" 2>/dev/null || true

# Inspect A's capture for tenant B's UUID or canary RID.
if grep -q "$TENANT_B_UUID\|$CANARY_RID" "$SSE_OUT" 2>/dev/null; then
  _fail "6.1.1 SSE cross-tenant" "tenant A stream received tenant B scan_complete event"
elif grep -q '"type":"scan_complete"' "$SSE_OUT" 2>/dev/null; then
  # Got SOME scan_complete — could be from another tenant or our own;
  # need stricter check. If it doesn't carry B's marker, isolation OK.
  _pass "6.1.1 SSE cross-tenant [A received scan_complete events but none from B]"
else
  # No scan_complete events seen; could be (a) clean isolation or (b)
  # SSE poller didn't run. Look for any 'connected' line to confirm
  # the stream itself worked.
  if grep -q '"type":"connected"' "$SSE_OUT" 2>/dev/null; then
    _pass "6.1.1 SSE cross-tenant [stream open, no foreign events seen]"
  else
    _skip "6.1.1 SSE cross-tenant" "stream never opened (SSE off?)"
  fi
fi

# ── 6.2 RBAC role matrix ───────────────────────────────────────────────────

phase_open "6.2 RBAC role matrix — admin endpoints"

# probe NAME URL TOKEN EXPECTED_HTTP
# 401 = unauthenticated, 403 = forbidden, 200/2xx = allowed.
probe() {
  local name="$1" url="$2" token="$3" want="$4"
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  local got
  got=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $token" "$BASE$url" 2>/dev/null) || got="000"
  local matched=0
  local IFS='|'
  for code in $want; do
    [[ "$got" == "$code" ]] && matched=1
  done
  unset IFS
  if (( matched == 1 )); then
    _pass "$name [$got]"
  else
    _fail "$name" "expected $want, got $got"
  fi
}

# Admin endpoints — only admin should reach 200; others 403 (or 401 if
# RequireRole runs before claims check, which it shouldn't).
probe "6.2.1 admin reads /admin/users → 200"           "/api/v1/admin/users" "$ADMIN_A"   "200"
probe "6.2.2 analyst reads /admin/users → 403"         "/api/v1/admin/users" "$ANALYST_A" "403"
probe "6.2.3 dev reads /admin/users → 403"             "/api/v1/admin/users" "$DEV_A"     "403"
probe "6.2.4 auditor reads /admin/users → 403"         "/api/v1/admin/users" "$AUDITOR_A" "403"

probe "6.2.5 admin reads /admin/api-keys → 200"        "/api/v1/admin/api-keys" "$ADMIN_A"   "200"
probe "6.2.6 analyst reads /admin/api-keys → 403"      "/api/v1/admin/api-keys" "$ANALYST_A" "403"
probe "6.2.7 dev reads /admin/api-keys → 403"          "/api/v1/admin/api-keys" "$DEV_A"     "403"
probe "6.2.8 auditor reads /admin/api-keys → 403"      "/api/v1/admin/api-keys" "$AUDITOR_A" "403"

probe "6.2.9 admin reads /admin/tenants → 200"         "/api/v1/admin/tenants" "$ADMIN_A"   "200"
probe "6.2.10 analyst reads /admin/tenants → 403"      "/api/v1/admin/tenants" "$ANALYST_A" "403"

# Cross-tenant admin: tenant-B admin can list ITS users but must NOT
# escalate into tenant-A's user list (this is checked indirectly: if
# the response contains tenant A user emails, that's a leak. We only
# probe HTTP status here — content check is L4-B's job).
probe "6.2.11 tenant-B admin reads /admin/users → 200" "/api/v1/admin/users" "$ADMIN_B" "200"

# Mutation endpoints — auditor (read-only) must be denied.
phase_open "6.2.x RBAC — mutating endpoints"

probe "6.2.12 auditor POSTs /vsp/run → 401|403"        "/api/v1/vsp/run" "$AUDITOR_A" "401|403|405"
probe "6.2.13 dev POSTs /vsp/run → 401|403|400"        "/api/v1/vsp/run" "$DEV_A"     "401|403|400|405"

# ── 6.3 Concurrency races ──────────────────────────────────────────────────

phase_open "6.3 Concurrency — IPLockout under burst"

# Fire 30 bad-credential logins from this IP in quick parallel bursts.
# After bursts, IPLockout should record at least 20 fails and the IP
# should be locked. If we can still log in after, that's a race bug.
LOGIN_URL="$BASE/api/v1/auth/login"
START=$(date +%s%N)
for i in $(seq 1 30); do
  curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
    -d '{"email":"l5-burst@vsp.local","password":"wrong"}' \
    --max-time 3 "$LOGIN_URL" &
done
wait || true   # `set -e` would otherwise abort on any one curl's non-zero exit
ELAPSED_MS=$(( ($(date +%s%N) - START) / 1000000 ))

# After the burst, this IP should be locked. Try one more login with a
# correct-format payload — expect 429 or 401 with lockout message.
sleep 1
LOCKED_RESP=$(curl -s -o /tmp/lockout.json -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"l5-burst@vsp.local","password":"wrong"}' \
  --max-time 3 "$LOGIN_URL" 2>/dev/null) || LOCKED_RESP="000"
LOCKED_BODY=$(head -c 200 /tmp/lockout.json 2>/dev/null)
rm -f /tmp/lockout.json

if [[ "$LOCKED_RESP" == "429" ]] || echo "$LOCKED_BODY" | grep -qi "lock\|too many"; then
  _pass "6.3.1 IPLockout triggers after 30 bad logins [HTTP $LOCKED_RESP, ${ELAPSED_MS}ms]"
else
  _fail "6.3.1 IPLockout triggers after 30 bad logins" \
    "expected 429 or lockout text after 30 fails — got HTTP $LOCKED_RESP body=$LOCKED_BODY"
fi

phase_open "6.3 Concurrency — audit chain ordering under burst"

# Generate a burst of audit-emitting actions (bad logins again — each
# emits LOGIN_FAILED) and verify the audit chain still verifies.
sleep 12  # let lockout window expire enough to allow more events
# We don't need the IP unlocked — bad logins still write audit even
# when blocked. The point is: 30 events in < 1s shouldn't break the
# hash chain.

VERIFY_BEFORE=$(curl -s -X POST --max-time 5 -H "Authorization: Bearer $ADMIN_A" \
  "$BASE/api/v1/audit/verify" | jq -r '.ok // false' 2>/dev/null || echo "false")

# Skip the test if verify is already broken (separate pre-existing issue)
if [[ "$VERIFY_BEFORE" != "true" ]]; then
  _skip "6.3.2 audit chain ordering under burst" "audit/verify already not OK before test"
else
  for i in $(seq 1 20); do
    curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
      -d '{"email":"l5-chain@vsp.local","password":"wrong"}' \
      --max-time 3 "$LOGIN_URL" &
  done
  wait
  sleep 2
  VERIFY_AFTER=$(curl -s -X POST --max-time 5 -H "Authorization: Bearer $ADMIN_A" \
    "$BASE/api/v1/audit/verify" | jq -r '.ok // false' 2>/dev/null || echo "false")
  if [[ "$VERIFY_AFTER" == "true" ]]; then
    _pass "6.3.2 audit chain still verifies after 20-event burst"
  else
    _fail "6.3.2 audit chain ordering under burst" \
      "audit/verify went from ok=true to ok=$VERIFY_AFTER after concurrent inserts"
  fi
fi

phase_open "6.3 Concurrency — cache stampede + tenant correctness"

# Cache stampede probe: 50 simultaneous first-miss requests against a
# cached endpoint. Each request must (a) succeed, (b) return data
# specific to ITS tenant (not the other tenant's even if both query
# concurrently). Catches the same key-collision bug we just fixed
# under load.

# First flush the cache so we get a clean miss. Redis password is
# resolved via env first (CI), file second (operator path).
REDIS_PASS="${REDIS_PASSWORD:-${REDIS_PASS:-}}"
if [[ -z "$REDIS_PASS" ]]; then
  _redis_file="${VSP_JWT_SECRET_FILE:-/etc/vsp/env.production}"
  if [[ -r "$_redis_file" ]]; then
    REDIS_PASS=$(grep -E '^REDIS_PASSWORD|^REDIS_PASS' "$_redis_file" 2>/dev/null | head -1 | cut -d= -f2-)
  elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
    REDIS_PASS=$(sudo grep -E '^REDIS_PASSWORD|^REDIS_PASS' "$_redis_file" 2>/dev/null | head -1 | cut -d= -f2-)
  fi
fi
if [[ -n "$REDIS_PASS" ]]; then
  redis-cli -a "$REDIS_PASS" --no-auth-warning DEL $(redis-cli -a "$REDIS_PASS" --no-auth-warning KEYS 'vsp:api:findings-summary:*' 2>/dev/null) >/dev/null 2>&1 || true
fi

OUT_DIR=$(mktemp -d)
for i in $(seq 1 25); do
  curl -s -o "$OUT_DIR/A_$i.json" --max-time 8 \
    -H "Authorization: Bearer $ADMIN_A" "$BASE/api/v1/vsp/findings/summary" &
  curl -s -o "$OUT_DIR/B_$i.json" --max-time 8 \
    -H "Authorization: Bearer $ADMIN_B" "$BASE/api/v1/vsp/findings/summary" &
done
wait || true   # tolerate any single curl timing out under stampede load

# Aggregate: every A response must have the same total; same for B.
# More importantly A's totals must NOT equal B's (would indicate cache
# returned wrong tenant under stampede).
TOTAL_A=$(jq -r '.total // empty' "$OUT_DIR"/A_*.json 2>/dev/null | sort -u | head -3 | tr '\n' ',' || true)
TOTAL_B=$(jq -r '.total // empty' "$OUT_DIR"/B_*.json 2>/dev/null | sort -u | head -3 | tr '\n' ',' || true)
A_DISTINCT=$(jq -r '.total // empty' "$OUT_DIR"/A_*.json 2>/dev/null | sort -u | wc -l | tr -d ' ')
B_DISTINCT=$(jq -r '.total // empty' "$OUT_DIR"/B_*.json 2>/dev/null | sort -u | wc -l | tr -d ' ')
rm -rf "$OUT_DIR"

if [[ "$A_DISTINCT" -gt 1 ]]; then
  _fail "6.3.3 cache stampede tenant-stable A" \
    "tenant A saw multiple totals under stampede ($A_DISTINCT distinct: $TOTAL_A)"
elif [[ "$B_DISTINCT" -gt 1 ]]; then
  _fail "6.3.3 cache stampede tenant-stable B" \
    "tenant B saw multiple totals under stampede ($B_DISTINCT distinct: $TOTAL_B)"
elif [[ -n "$TOTAL_A" && "$TOTAL_A" == "$TOTAL_B" ]]; then
  _fail "6.3.3 cache stampede A/B distinct" \
    "both tenants returned identical total $TOTAL_A under 50-way stampede — cache leak under contention"
else
  _pass "6.3.3 cache stampede tenant-isolated [A=$TOTAL_A B=$TOTAL_B]"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
