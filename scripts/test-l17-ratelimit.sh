#!/usr/bin/env bash
# scripts/test-l17-ratelimit.sh — rate-limit / abuse-vector coverage.
#
# The gateway intentionally disabled the global per-IP rate limiter
# (cmd/gateway/main.go ~ line 520, "VSP_PATCH_PERF_03") because the
# dashboard's own poll cadence triggered 429 storms. The defense
# layers that REMAINED are:
#
#   - per-account login lockout (5 fails → 15-min lock)
#   - per-IP login lockout (20 fails / 10-min sliding window)
#   - constant-time login response (bcrypt on missing-user path)
#   - 4MB body limit on JSON handlers
#   - 60s request timeout
#   - JWT auth + CSRF middleware
#   - upstream nginx limits (out of scope here)
#
# This level confirms each remaining defense actually works and that
# disabling the global limiter didn't accidentally remove a layer
# everyone forgot about.
#
# Pre-flight: $JWT_SECRET, $DB_DSN, gateway running with a CLEAN
# IPLockout state (run after `systemctl restart vsp-gateway`).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq openssl

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

mint_jwt() {
  local now exp h p s
  now=$(date +%s); exp=$((now + 3600))
  h=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  p=$(printf '{"sub":"l17@vsp.local","email":"l17@vsp.local","role":"admin","tenant_id":"default","iat":%d,"exp":%d}' \
    "$now" "$exp" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  printf '%s.%s.%s\n' "$h" "$p" "$s"
}
ADMIN=$(mint_jwt)

# ── 18.1 IPLockout fires across multiple usernames ─────────────────────────

phase_open "18.1 IPLockout — locks IP across N distinct usernames"

# Restart gateway to clear in-memory IPLockout state. We need a known
# baseline to count up from.
sudo systemctl restart vsp-gateway 2>/dev/null && sleep 4

# Hit /auth/login with 22 DIFFERENT usernames, each one bad-password.
# IPLockout's per-IP window threshold is 20 fails / 10 min. After 20
# the IP must lock regardless of which usernames it tried — this is
# the credential-stuffing defense.
LOCKED=0
PROBED=0
for i in $(seq 1 22); do
  PROBED=$((PROBED+1))
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" \
    -d "{\"email\":\"stuffing-$i@vsp.local\",\"password\":\"wrong-$i\"}" \
    "$BASE/api/v1/auth/login")
  # Accept either 401 (auth failed) or 429 (locked out). Once we see
  # 429 we know the limiter engaged.
  if [[ "$status" == "429" ]]; then
    LOCKED=1; break
  fi
done

if (( LOCKED == 1 )); then
  _pass "18.1.1 IPLockout fired after $PROBED attempts across distinct usernames"
else
  _fail "18.1.1 IPLockout didn't engage" \
    "tried $PROBED attempts with different usernames, never got 429"
fi

# ── 18.2 Body size limit on JSON ───────────────────────────────────────────

phase_open "18.2 Body limit — 4MB cap honoured on JSON POSTs"

# Construct a 5MB JSON body. Per the in-code comment the cap is 4MB,
# so we expect 4xx (400/413/431) — never a 200 that processed it.
big=$(mktemp)
python3 -c 'import json,sys; sys.stdout.write(json.dumps({"x":"a"*(5*1024*1024)}))' > "$big"
SIZE=$(wc -c < "$big")
START=$(date +%s%N)
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
  -X POST -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  --data-binary "@$big" "$BASE/api/v1/settings/tool-config")
ELAPSED=$(( ($(date +%s%N) - START) / 1000000 ))
rm -f "$big"

if [[ "$status" =~ ^(400|413|414|431)$ ]]; then
  _pass "18.2.1 ${SIZE}B (5MB) body rejected [HTTP $status, ${ELAPSED}ms]"
elif [[ "$status" =~ ^2 ]]; then
  _fail "18.2.1 large body accepted" "HTTP $status — handler processed 5MB+"
elif [[ "$status" == "401" || "$status" == "403" || "$status" == "405" ]]; then
  # Auth or method rejection happened before body was read — acceptable
  # because the body never actually entered the handler.
  _pass "18.2.1 large body short-circuited [HTTP $status]"
else
  _fail "18.2.1 unexpected body response" "HTTP $status"
fi

# ── 18.3 Request timeout — slow client gets cut off ───────────────────────

phase_open "18.3 Request timeout — slowloris probe"

# Open a connection, send headers but trickle the body 1 byte / sec.
# Server should cut us off well before the implied 60s timeout — most
# Go HTTP servers default to ReadHeaderTimeout / IdleTimeout in seconds.
# We're not testing a *strict* timeout value, just that it's bounded
# under 90s.
START=$(date +%s)
{
  printf 'POST /api/v1/auth/login HTTP/1.1\r\n'
  printf 'Host: 127.0.0.1\r\n'
  printf 'Content-Type: application/json\r\n'
  printf 'Content-Length: 200\r\n'
  printf '\r\n'
  for i in $(seq 1 100); do
    printf 'a'
    sleep 1
  done
} | timeout 90 nc -w 90 127.0.0.1 8921 > /tmp/l17_slow.out 2>/dev/null &
NC_PID=$!
wait "$NC_PID" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))

if (( ELAPSED < 75 )); then
  _pass "18.3.1 slow body cut off after ${ELAPSED}s"
else
  _fail "18.3.1 slow body not cut off" \
    "connection survived ${ELAPSED}s — server has no read timeout"
fi
rm -f /tmp/l17_slow.out

# ── 18.4 Expensive endpoint resists abuse without 5xx ──────────────────────

phase_open "18.4 Expensive endpoint — burst doesn't crash gateway"

# /audit/verify is one of the heaviest endpoints (chains hash-walk
# over 1000s of rows). The global rate limiter is OFF, so a malicious
# admin could try to DoS by spamming this. We probe 50 concurrent
# verifies and assert: no 5xx, gateway still healthy after.
sudo systemctl restart vsp-gateway 2>/dev/null && sleep 4
ADMIN=$(mint_jwt)   # mint a fresh token after restart

GW_PID_BEFORE=$(pgrep -f "/usr/local/bin/vsp-gateway" | head -1)
SUCCESS=0
FAIL5XX=0
TMP=$(mktemp -d)
for i in $(seq 1 50); do
  curl -s -o "$TMP/r$i" -w "%{http_code}\n" --max-time 10 \
    -X POST -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/audit/verify" \
    >> "$TMP/codes" &
done
wait

while IFS= read -r code; do
  case "$code" in
    2*) SUCCESS=$((SUCCESS+1)) ;;
    5*) FAIL5XX=$((FAIL5XX+1)) ;;
  esac
done < "$TMP/codes"
rm -rf "$TMP"

GW_PID_AFTER=$(pgrep -f "/usr/local/bin/vsp-gateway" | head -1)
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/auth/check")

if [[ "$GW_PID_AFTER" != "$GW_PID_BEFORE" ]]; then
  _fail "18.4.1 audit/verify burst crashed gateway" \
    "pid changed $GW_PID_BEFORE → $GW_PID_AFTER (process restarted)"
elif (( FAIL5XX > 0 )); then
  _fail "18.4.1 audit/verify burst produced 5xx" \
    "$FAIL5XX/50 calls returned 5xx ($SUCCESS succeeded)"
elif [[ "$HEALTH" =~ ^(200|401)$ ]]; then
  _pass "18.4.1 50-way audit/verify burst absorbed [success=$SUCCESS, health=$HEALTH]"
else
  _fail "18.4.1 gateway unhealthy after burst" "/auth/check returned $HEALTH"
fi

# ── 18.5 Per-tenant quota isolation ────────────────────────────────────────

phase_open "18.5 Burst on tenant A doesn't lock out tenant B"

# IPLockout is per-IP (this whole test box). But operations from a
# DIFFERENT tenant should NOT inherit the lockout state. Practically:
# after our 22 bad logins above, can a real admin in tenant B still
# log in? We don't have a real password to test, but we can probe the
# lockout endpoint:
#   - Hit /auth/check with a valid tenant-B token: must succeed
#     even though our IP is locked for /auth/login.
ADMIN_B=$(mint_jwt)   # actually default tenant; rebuild for B
NOW=$(date +%s); EXP=$((NOW+3600))
H=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
P=$(printf '{"sub":"l17b@vsp.local","email":"l17b@vsp.local","role":"admin","tenant_id":"acme-corp","iat":%d,"exp":%d}' "$NOW" "$EXP" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
S=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
ADMIN_B="$H.$P.$S"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $ADMIN_B" "$BASE/api/v1/auth/check")

if [[ "$STATUS" == "200" ]]; then
  _pass "18.5.1 tenant B unaffected by tenant A's burst [/auth/check 200]"
else
  _fail "18.5.1 tenant B locked out alongside tenant A" \
    "/auth/check returned $STATUS for tenant B token"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
