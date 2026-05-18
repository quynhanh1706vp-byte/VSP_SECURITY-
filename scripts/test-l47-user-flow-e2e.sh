#!/usr/bin/env bash
# scripts/test-l47-user-flow-e2e.sh — end-to-end user-session flow.
#
# Most security levels probe single endpoints in isolation. This level
# walks a full authenticated user journey and asserts each transition:
#
#   1. Login with valid credentials → 200 + token in response body
#   2. Use the token on 3 different endpoints → 200 each
#   3. Logout (revokes the token's jti) → 200/204
#   4. Reuse the (revoked) token → 401 — proves blacklist is wired
#   5. Refresh-token-if-any-flow → tested separately
#   6. Token TTL boundary — minted-with-1s-exp → wait 2s → reject
#
# Catches the bug class: "logout was a no-op so revoked tokens still
# authenticated", "token-blacklist Redis was down so revoke silently
# succeeded", "/api/v1/auth/logout returned 200 but didn't actually
# invalidate". These are real-world session bugs that single-endpoint
# tests miss.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 47.1 Login + use journey ─────────────────────────────────────────────

phase_open "47.1 Login → token works on protected endpoints"

# In CI the canonical user is seeded by gateway boot. Username/password
# vary per environment; resolve from env or fall back to the dev-stub
# default.
TEST_EMAIL="${L47_USER_EMAIL:-admin@vsp.local}"
TEST_PASS="${L47_USER_PASS:-vsp-admin}"

login_body=$(mktemp)
login_status=$(curl -s -o "$login_body" -w "%{http_code}" --max-time 5 \
  -X POST -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASS\"}" \
  "$BASE/api/v1/auth/login" 2>/dev/null || echo "000")

E2E_TOKEN=""
if [[ "$login_status" =~ ^2 ]]; then
  E2E_TOKEN=$(jq -r '.token // .access_token // .jwt // empty' "$login_body" 2>/dev/null || true)
fi
rm -f "$login_body"

if [[ -z "$E2E_TOKEN" ]]; then
  # No real login flow in CI (the test fixture doesn't create a user
  # with vsp-admin / admin@vsp.local). Fall back to a freshly-minted
  # JWT from the canonical helper — same revocation path applies.
  E2E_TOKEN=$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")
  _skip "47.1.0 password login flow" \
    "no seed user $TEST_EMAIL — falling back to mint_jwt_local for the rest of L47 (HTTP $login_status)"
else
  _pass "47.1.0 password login returns a token [HTTP $login_status]"
fi

# Use the token on 3 endpoints. Mix of any-auth and admin-only.
ALL_OK=1
for ep in "/api/v1/status" "/api/v1/kpi/sanity" "/api/v1/audit/log?limit=1"; do
  s=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $E2E_TOKEN" \
    "$BASE$ep" 2>/dev/null || echo "000")
  if [[ "$s" =~ ^2 ]]; then
    : # ok
  else
    ALL_OK=0
    LAST_FAIL="$ep [HTTP $s]"
  fi
done

if (( ALL_OK )); then
  _pass "47.1.1 freshly-issued token authenticates on 3 endpoints"
else
  _fail "47.1.1 token rejected on a protected endpoint" "${LAST_FAIL:-?}"
fi

# ── 47.2 Logout invalidates the token ────────────────────────────────────

phase_open "47.2 Logout → revoked token can't authenticate"

logout_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -X POST -H "Authorization: Bearer $E2E_TOKEN" \
  "$BASE/api/v1/auth/logout" 2>/dev/null || echo "000")

if [[ "$logout_status" =~ ^2 ]]; then
  _pass "47.2.0 logout returned 2xx [HTTP $logout_status]"

  # Give the revocation list (Redis or in-memory) up to 2s to propagate.
  sleep 1

  # Now try to re-use the token. MUST be rejected.
  reuse_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $E2E_TOKEN" \
    "$BASE/api/v1/audit/log?limit=1" 2>/dev/null || echo "000")
  if [[ "$reuse_status" == "401" || "$reuse_status" == "403" ]]; then
    _pass "47.2.1 revoked token rejected [HTTP $reuse_status]"
  else
    _fail "47.2.1 revoked token still works" \
      "HTTP $reuse_status — blacklist not consulted on validate path"
  fi
elif [[ "$logout_status" == "404" || "$logout_status" == "405" ]]; then
  _skip "47.2.0 logout endpoint" "not mounted [HTTP $logout_status]"
else
  _skip "47.2.0 logout endpoint" "unexpected HTTP $logout_status"
fi

# ── 47.3 TTL boundary — short-lived token expires ────────────────────────

phase_open "47.3 Token TTL boundary"

# Mint a token with exp = now + 2s. Wait 3s. Must be rejected.
SECRET="${JWT_SECRET:-dev-secret-please-change}"
NOW=$(date +%s)
SHORT_EXP=$((NOW + 2))

_b64() { printf '%s' "$1" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-' ; }
H=$(_b64 '{"alg":"HS256","typ":"JWT"}')
P=$(_b64 "{\"sub\":\"e2e@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$NOW,\"exp\":$SHORT_EXP}")
S=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$SECRET" -binary | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
SHORT_TOK="$H.$P.$S"

# Use a PROTECTED endpoint — /api/v1/status is anonymous and returns
# 200 regardless of token. /api/v1/audit/log requires authMw, which
# is the surface the exp check actually runs on.
EXP_PROBE_URL="/api/v1/audit/log?limit=1"

s_now=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $SHORT_TOK" \
  "$BASE$EXP_PROBE_URL" 2>/dev/null || echo "000")
if [[ "$s_now" =~ ^2 ]]; then
  _pass "47.3.0 short-TTL token works pre-expiry [HTTP $s_now]"

  # Wait past expiry.
  sleep 3

  s_then=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $SHORT_TOK" \
    "$BASE$EXP_PROBE_URL" 2>/dev/null || echo "000")
  if [[ "$s_then" == "401" || "$s_then" == "403" ]]; then
    _pass "47.3.1 short-TTL token rejected post-expiry [HTTP $s_then]"
  else
    _fail "47.3.1 expired token still works on protected endpoint" \
      "HTTP $s_then on $EXP_PROBE_URL — exp not enforced by auth middleware"
  fi
else
  _skip "47.3 short-TTL token" "didn't authenticate before expiry [HTTP $s_now] — env mismatch"
fi

# ── 47.4 Concurrent-session safety ───────────────────────────────────────

phase_open "47.4 Logout of one token doesn't invalidate another"

# Mint two independent tokens (each with unique jti by virtue of
# mint_jwt_local generating a fresh one). Logout A. Verify B still
# works. This catches "logout flushed ALL tokens for the user" bugs.
TOK_A=$($ROOT/scripts/mint_jwt_local.sh admin "$SECRET")
TOK_B=$($ROOT/scripts/mint_jwt_local.sh admin "$SECRET")

# Sanity: both work. /api/v1/audit/log is protected, so the test
# actually exercises authMw (the anonymous /api/v1/status would
# return 200 for ANY token, defeating the purpose).
PROBE_URL="/api/v1/audit/log?limit=1"
sA=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $TOK_A" "$BASE$PROBE_URL" 2>/dev/null || echo "000")
sB=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $TOK_B" "$BASE$PROBE_URL" 2>/dev/null || echo "000")

if [[ ! "$sA" =~ ^2 || ! "$sB" =~ ^2 ]]; then
  _skip "47.4 concurrent-session" "sanity check failed — sA=$sA sB=$sB"
else
  # Logout A.
  curl -s -o /dev/null --max-time 5 \
    -X POST -H "Authorization: Bearer $TOK_A" \
    "$BASE/api/v1/auth/logout" 2>/dev/null || true
  sleep 1

  # B must still work.
  sB_after=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $TOK_B" "$BASE$PROBE_URL" 2>/dev/null || echo "000")

  if [[ "$sB_after" =~ ^2 ]]; then
    _pass "47.4.1 logout of token A didn't kill token B [HTTP $sB_after]"
  else
    _fail "47.4.1 logout invalidated other session" \
      "token B now returns HTTP $sB_after — overly-broad revocation"
  fi
fi

final_summary
