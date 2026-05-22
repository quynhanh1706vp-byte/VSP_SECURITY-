#!/usr/bin/env bash
# scripts/test-l29-time-correctness.sh — time / timezone correctness.
#
# Five probes:
#
#   30.1 Audit log timestamps stored in UTC (or with offset) — never
#        naive local times. created_at columns must be timestamptz.
#
#   30.2 JWT exp boundary — token expired by 1 second is rejected,
#        token with exp=now+1s is accepted.
#
#   30.3 Future-dated row detection — no DB row exists with
#        created_at > NOW() + 5min. (Guards against clock skew or
#        a buggy time-source.)
#
#   30.4 Locale invariance — POST with Accept-Language: vi vs en gets
#        same status / shape (only message text changes).
#
#   30.5 No use of time.Local in security-sensitive code. zone-aware
#        comparisons must use time.UTC.
#
# Pre-flight: $JWT_SECRET, $DB_DSN, gateway running.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq psql openssl

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

# ── 30.1 Audit log columns are timestamptz ────────────────────────────────

phase_open "30.1 Time columns — timestamptz on tenant-scoped tables"

# A timestamp without time zone column silently uses session TZ for
# comparisons → cross-region replicas get inconsistent ordering.
# Probe critical tenant-scoped tables.
NAIVE=()
for tbl in audit_log findings runs users compliance_evidence \
           data_subject_requests; do
  exists=$(_psql_oneshot "SELECT to_regclass('public.$tbl') IS NOT NULL")
  [[ "$exists" != "t" ]] && continue
  cols_naive=$(_psql_oneshot "SELECT count(*) FROM information_schema.columns
                              WHERE table_name='$tbl'
                                AND data_type='timestamp without time zone';")
  cols_naive=${cols_naive:-0}
  if (( cols_naive > 0 )); then
    NAIVE+=("$tbl ($cols_naive cols)")
  fi
done

if (( ${#NAIVE[@]} == 0 )); then
  _pass "30.1.1 every probed time column is timestamptz"
else
  _fail "30.1.1 naive timestamp columns" "${NAIVE[*]}"
fi

# ── 30.2 JWT exp boundary ─────────────────────────────────────────────────

phase_open "30.2 JWT exp boundary — expired-by-1s rejected"

mint() {
  local exp_offset="$1"
  local now exp h p s
  now=$(date +%s); exp=$((now + exp_offset))
  h=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  p=$(printf '{"sub":"l29@vsp.local","email":"l29@vsp.local","role":"admin","tenant_id":"default","iat":%d,"exp":%d}' \
    "$now" "$exp" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  printf '%s.%s.%s\n' "$h" "$p" "$s"
}

# Token expired 1 second ago.
PAST=$(mint -1)
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $PAST" "$BASE/api/v1/auth/check")
if [[ "$status" == "401" ]]; then
  _pass "30.2.1 expired-by-1s token rejected [$status]"
else
  _fail "30.2.1 expired token accepted" "HTTP $status (expected 401)"
fi

# Token expiring in 60s should work fine.
FUTURE=$(mint 60)
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $FUTURE" "$BASE/api/v1/auth/check")
if [[ "$status" == "200" ]]; then
  _pass "30.2.2 60s-future-exp token accepted [$status]"
else
  _fail "30.2.2 valid token rejected" "HTTP $status (expected 200)"
fi

# ── 30.3 No future-dated rows ─────────────────────────────────────────────

phase_open "30.3 No future-dated rows — clock-skew detector"

FUTURE_AUDIT=$(_psql_oneshot "SELECT count(*) FROM audit_log
                              WHERE created_at > NOW() + INTERVAL '5 minutes';")
FUTURE_RUNS=$(_psql_oneshot "SELECT count(*) FROM runs
                              WHERE created_at > NOW() + INTERVAL '5 minutes';")

if (( FUTURE_AUDIT == 0 && FUTURE_RUNS == 0 )); then
  _pass "30.3.1 no future-dated rows in audit_log / runs"
else
  _fail "30.3.1 future-dated rows present" \
    "audit=$FUTURE_AUDIT, runs=$FUTURE_RUNS — possible clock-skew or rogue insert"
fi

# ── 30.4 Locale invariance — same status across languages ────────────────

phase_open "30.4 Locale invariance — vi vs en return same status"

S_VI=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
  -H "Accept-Language: vi" "$BASE/api/v1/status")
S_EN=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
  -H "Accept-Language: en" "$BASE/api/v1/status")

if [[ "$S_VI" == "$S_EN" ]]; then
  _pass "30.4.1 same status across locales [vi=$S_VI, en=$S_EN]"
else
  _fail "30.4.1 status differs by locale" "vi=$S_VI vs en=$S_EN"
fi

# ── 30.5 No time.Local in security-sensitive code ─────────────────────────

phase_open "30.5 No time.Local in auth / audit / token paths"

LOCAL_HITS=$(grep -rEn 'time\.Local\b|time\.LoadLocation' \
  --include="*.go" -- "$ROOT/internal/auth" "$ROOT/internal/audit" \
  "$ROOT/internal/api/handler/auth.go" "$ROOT/internal/api/handler/audit.go" \
  2>/dev/null | grep -v "_test\|\.bak" || true)

if [[ -z "$LOCAL_HITS" ]]; then
  _pass "30.5.1 auth/audit code uses time.UTC consistently"
else
  HITS=$(echo "$LOCAL_HITS" | head -3 | tr '\n' '|')
  _fail "30.5.1 time.Local in auth/audit" "$HITS"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
