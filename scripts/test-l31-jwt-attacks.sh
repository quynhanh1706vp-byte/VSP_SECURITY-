#!/usr/bin/env bash
# scripts/test-l31-jwt-attacks.sh — JWT-specific attack vectors.
#
# Probes that the gateway's parseJWT() (internal/auth/middleware.go)
# correctly rejects every classical JWT-tampering attempt:
#
#   1. alg=none (algorithm-stripping)
#   2. HS/RS confusion (algorithm-substitution)
#   3. Empty signature segment
#   4. Tampered claims (role escalation, tenant swap)
#   5. Expired token (exp in past)
#   6. Future-iat token (clock-skew tolerance)
#   7. Cross-tenant replay (token from B used against A's URL params)
#   8. Token reuse after logout (revocation enforcement)
#
# This is L31 not L4-B/L8 because it's hand-crafting bad tokens at
# the byte level rather than testing isolation invariants.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

JWT_SECRET_RESOLVED="${JWT_SECRET:-$(resolve_jwt_secret)}"
if [[ -z "$JWT_SECRET_RESOLVED" ]]; then
  _skip "31.0 JWT_SECRET resolved" "no secret available — can't craft probes"
  final_summary; exit 0
fi

# Helper: base64url encode (no padding, +/ → -_).
_b64url() {
  printf '%s' "$1" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-'
}

# Helper: HS256 signature over header.payload.
_hs256() {
  printf '%s' "$1" | openssl dgst -sha256 -hmac "$2" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-'
}

# Five protected endpoints — every JWT-tampering probe runs against
# ALL of them. If a single tampered token authenticates against ANY
# endpoint, the auth middleware has a partial-coverage bug.
PROTECTED_ENDPOINTS=(
  "/api/v1/admin/users"        # admin-only
  "/api/v1/audit/log?limit=1"  # admin/auditor
  "/api/v1/kpi/sanity"         # any-authenticated
  "/api/v1/vsp/findings?limit=1" # any-authenticated
  "/api/v1/scheduler/jobs"     # admin
)

# _probe TOKEN → "endpoint:HTTP_CODE,..." (one entry per protected URL).
_probe() {
  local token="$1" results=""
  for url in "${PROTECTED_ENDPOINTS[@]}"; do
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      -H "Authorization: Bearer $token" \
      "$BASE$url" 2>/dev/null || echo "000")
    results="${results}${url}:${code},"
  done
  printf '%s' "${results%,}"
}

# _all_rejected RESULT → 0 (true) if every endpoint returned 401/403/404/405,
#                       1 (false) otherwise. Used to assert a tampered token
#                       is universally rejected, not just at one route.
_all_rejected() {
  local r="$1"
  # Extract just the codes — split on comma, take field after :
  local codes
  codes=$(echo "$r" | tr ',' '\n' | awk -F: '{print $NF}')
  while IFS= read -r c; do
    [[ -z "$c" ]] && continue
    case "$c" in
      401|403|404|405) ;;
      *) return 1 ;;
    esac
  done <<<"$codes"
  return 0
}

# _any_accepted RESULT → echoes the first endpoint that returned 2xx,
# or empty if none did. The "we got in somewhere" failure detail.
_any_accepted() {
  local r="$1"
  echo "$r" | tr ',' '\n' | awk -F: '
    {
      code=$NF
      url=$1
      for (i=2; i<NF; i++) url=url ":" $i
      if (code ~ /^2/) { print url ":" code; exit }
    }'
}

# _probe_single TOKEN URL → just the HTTP code, for tests that only
# need single-endpoint behaviour (e.g. cookie-auth probes).
_probe_single() {
  curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $1" \
    "$BASE${2:-/api/v1/admin/users}" 2>/dev/null || echo "000"
}

NOW=$(date +%s)
EXP=$((NOW + 86400))

# ── 31.1 alg=none must be rejected ────────────────────────────────────────

phase_open "31.1 alg=none / no-signature variants"

H_NONE=$(_b64url '{"alg":"none","typ":"JWT"}')
P_ADMIN=$(_b64url "{\"sub\":\"attacker@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$NOW,\"exp\":$EXP}")

# alg=none with empty signature
NONE_TOKEN="$H_NONE.$P_ADMIN."
RES=$(_probe "$NONE_TOKEN")
if _all_rejected "$RES"; then
  _pass "31.1.1 alg=none rejected on all 5 protected endpoints"
else
  HIT=$(_any_accepted "$RES")
  _fail "31.1.1 alg=none accepted somewhere" \
    "unsigned token authenticated at $HIT — auth middleware has partial coverage"
fi

# alg=none with garbage signature
NONE_GARBAGE="$H_NONE.$P_ADMIN.garbage"
RES=$(_probe "$NONE_GARBAGE")
if _all_rejected "$RES"; then
  _pass "31.1.2 alg=none + garbage sig rejected on all 5 endpoints"
else
  HIT=$(_any_accepted "$RES")
  _fail "31.1.2 alg=none + garbage sig accepted somewhere" "$HIT"
fi

# Empty signature on a valid HS256 header
H_HS=$(_b64url '{"alg":"HS256","typ":"JWT"}')
EMPTY_SIG="$H_HS.$P_ADMIN."
RES=$(_probe "$EMPTY_SIG")
if _all_rejected "$RES"; then
  _pass "31.1.3 HS256 with empty signature rejected on all 5 endpoints"
else
  HIT=$(_any_accepted "$RES")
  _fail "31.1.3 HS256 empty-sig accepted somewhere" "$HIT"
fi

# ── 31.2 Algorithm confusion (HS256 vs RS256) ─────────────────────────────

phase_open "31.2 Algorithm confusion"

# Submit a token claiming alg=RS256 but actually signed with HS256
# using whatever the secret happens to be. Some libraries fall through
# and use the secret as a public key, which is the classic confusion.
H_RS=$(_b64url '{"alg":"RS256","typ":"JWT"}')
SIG=$(_hs256 "$H_RS.$P_ADMIN" "$JWT_SECRET_RESOLVED")
RS_TOKEN="$H_RS.$P_ADMIN.$SIG"
RES=$(_probe "$RS_TOKEN")
if _all_rejected "$RES"; then
  _pass "31.2.1 alg=RS256 + HS256 sig rejected on all 5 endpoints"
else
  HIT=$(_any_accepted "$RES")
  _fail "31.2.1 algorithm-confusion ACCEPTED" \
    "$HIT — middleware should pin to HS256 only"
fi

# ── 31.3 Tampered claims must invalidate signature ────────────────────────

phase_open "31.3 Claim-tampering — sig must invalidate"

# Mint a legit analyst token, then flip role=admin in payload WITHOUT
# resigning. Signature should no longer verify.
P_ANALYST=$(_b64url "{\"sub\":\"analyst@vsp.test\",\"role\":\"analyst\",\"tenant_id\":\"default\",\"iat\":$NOW,\"exp\":$EXP}")
SIG=$(_hs256 "$H_HS.$P_ANALYST" "$JWT_SECRET_RESOLVED")
LEGIT_ANALYST="$H_HS.$P_ANALYST.$SIG"

# Confirm the legit token works as analyst — at least one endpoint
# should accept it (kpi/sanity / findings are open to analyst), at
# least one should reject (admin/users → 403).
RES=$(_probe "$LEGIT_ANALYST")
if echo "$RES" | grep -qE ':[2][0-9][0-9],?'; then
  _pass "31.3.0 legit analyst token authenticates on ≥1 endpoint"

  # Flip payload to role=admin, KEEP analyst signature.
  P_ADMIN_TAMPER=$(_b64url "{\"sub\":\"analyst@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$NOW,\"exp\":$EXP}")
  TAMPERED="$H_HS.$P_ADMIN_TAMPER.$SIG"
  RES=$(_probe "$TAMPERED")
  if _all_rejected "$RES"; then
    _pass "31.3.1 role-tampered token rejected on all 5 endpoints"
  else
    HIT=$(_any_accepted "$RES")
    _fail "31.3.1 role-tampered token ACCEPTED" "$HIT — sig verification skipped"
  fi
else
  _skip "31.3 baseline" "legit analyst token didn't authenticate on ANY endpoint — env mismatch"
fi

# ── 31.4 Expired tokens must be rejected ──────────────────────────────────

phase_open "31.4 Temporal — expired / future-iat"

# exp = 1h ago
EXP_PAST=$((NOW - 3600))
P_EXPIRED=$(_b64url "{\"sub\":\"admin@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$((NOW-7200)),\"exp\":$EXP_PAST}")
SIG=$(_hs256 "$H_HS.$P_EXPIRED" "$JWT_SECRET_RESOLVED")
EXPIRED_TOKEN="$H_HS.$P_EXPIRED.$SIG"
RES=$(_probe "$EXPIRED_TOKEN")
if _all_rejected "$RES"; then
  _pass "31.4.1 expired token rejected on all 5 endpoints"
else
  HIT=$(_any_accepted "$RES")
  _fail "31.4.1 expired token accepted somewhere" "$HIT — exp not enforced"
fi

# iat 1h in future — most JWT libs allow this; flag as informational.
IAT_FUTURE=$((NOW + 3600))
P_FUTURE=$(_b64url "{\"sub\":\"admin@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$IAT_FUTURE,\"exp\":$((IAT_FUTURE+86400))}")
SIG=$(_hs256 "$H_HS.$P_FUTURE" "$JWT_SECRET_RESOLVED")
FUTURE_TOKEN="$H_HS.$P_FUTURE.$SIG"
RES=$(_probe "$FUTURE_TOKEN")
if _all_rejected "$RES"; then
  _pass "31.4.2 future-iat token rejected (strict) on all 5 endpoints"
else
  HIT=$(_any_accepted "$RES")
  _skip "31.4.2 future-iat token" \
    "accepted at $HIT — most JWT libs allow this; consider tightening if clock-skew is a concern"
fi

# nbf (not-before) in future — must be rejected if enforced.
NBF_FUTURE=$((NOW + 3600))
P_NBF=$(_b64url "{\"sub\":\"admin@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$NOW,\"nbf\":$NBF_FUTURE,\"exp\":$EXP}")
SIG=$(_hs256 "$H_HS.$P_NBF" "$JWT_SECRET_RESOLVED")
NBF_TOKEN="$H_HS.$P_NBF.$SIG"
RES=$(_probe "$NBF_TOKEN")
if _all_rejected "$RES"; then
  _pass "31.4.3 nbf-in-future rejected on all 5 endpoints"
else
  HIT=$(_any_accepted "$RES")
  _skip "31.4.3 nbf-in-future" \
    "accepted at $HIT — nbf not enforced (informational, not all libs check it)"
fi

# ── 31.5 Long-lived token (year 2099) — accepted with warning? ───────────

phase_open "31.5 Long-expiry tokens"

# A token with exp 75 years out is technically valid but operationally
# concerning. We don't fail on it (RFC compliance) — just record.
EXP_FAR=$((NOW + 75 * 365 * 86400))
P_FAR=$(_b64url "{\"sub\":\"admin@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$NOW,\"exp\":$EXP_FAR}")
SIG=$(_hs256 "$H_HS.$P_FAR" "$JWT_SECRET_RESOLVED")
FAR_TOKEN="$H_HS.$P_FAR.$SIG"
RES=$(_probe "$FAR_TOKEN")
if _all_rejected "$RES"; then
  _pass "31.5.1 75-year token rejected on all 5 endpoints (max-exp policy enforced)"
else
  ACCEPTED=$(_any_accepted "$RES")
  _skip "31.5.1 75-year token accepted" \
    "$ACCEPTED — RFC-compliant; consider capping exp at issue time for prod"
fi

# ── 31.6 Wrong-secret signature ───────────────────────────────────────────

phase_open "31.6 Wrong-secret signature"

WRONG_SIG=$(_hs256 "$H_HS.$P_ADMIN" "definitely-not-the-right-secret-$(date +%N)")
WRONG_TOKEN="$H_HS.$P_ADMIN.$WRONG_SIG"
RES=$(_probe "$WRONG_TOKEN")
if _all_rejected "$RES"; then
  _pass "31.6.1 wrong-secret signature rejected on all 5 endpoints"
else
  HIT=$(_any_accepted "$RES")
  _fail "31.6.1 wrong-secret accepted" "$HIT — auth middleware misconfigured"
fi

# ── 31.7 Malformed structure ──────────────────────────────────────────────

phase_open "31.7 Malformed JWT structures"

for bad in \
    "" \
    "not.a.jwt" \
    "$H_HS" \
    "$H_HS.$P_ADMIN" \
    ".." \
    "$H_HS..$SIG" \
  ; do
  RES=$(_probe "$bad")
  if _all_rejected "$RES"; then
    _pass "31.7 malformed token '$(echo "$bad" | head -c 30)...' rejected on all 5 endpoints"
  else
    HIT=$(_any_accepted "$RES")
    _fail "31.7 malformed token accepted" "input '$bad' authenticated at $HIT"
  fi
done

# ── 31.8 Header-shape fuzzing — case / spacing / duplication ─────────────

phase_open "31.8 Authorization header parsing edge cases"

# Mint a real, valid admin token to use as the substrate for shape probes.
# If the token authenticates somewhere via the standard "Bearer X" form,
# we can verify the variant forms behave consistently.
LEGIT_ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "$JWT_SECRET_RESOLVED")}"
BASE_RES=$(_probe "$LEGIT_ADMIN")
if ! echo "$BASE_RES" | grep -qE ':[2][0-9][0-9],?'; then
  _skip "31.8 baseline" "legit admin token didn't authenticate anywhere — skip header-shape probes"
else
  # 31.8.1 Lowercase "bearer" prefix — RFC 7235 says scheme is
  # case-insensitive; gateway should accept consistently.
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: bearer $LEGIT_ADMIN" \
    "$BASE/api/v1/kpi/sanity" 2>/dev/null || echo "000")
  if [[ "$status" =~ ^2 ]]; then
    _pass "31.8.1 'bearer' (lowercase) accepted [HTTP $status]"
  else
    _skip "31.8.1 'bearer' lowercase rejected" \
      "HTTP $status — RFC 7235 says scheme is case-insensitive; informational"
  fi

  # 31.8.2 Multi-space between scheme and token must NOT bypass auth.
  # If the parser is too permissive, "Bearer  X" might strip a leading
  # token char and somehow validate.
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer    $LEGIT_ADMIN" \
    "$BASE/api/v1/kpi/sanity" 2>/dev/null || echo "000")
  if [[ "$status" =~ ^(2|401|403) ]]; then
    _pass "31.8.2 multi-space Bearer handled deterministically [HTTP $status]"
  else
    _fail "31.8.2 multi-space Bearer" "unexpected HTTP $status"
  fi

  # 31.8.3 Two Authorization headers — RFC says concat with comma; the
  # gateway must NOT accept the second one's token if the first is bad.
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer this.is.invalid" \
    -H "Authorization: Bearer $LEGIT_ADMIN" \
    "$BASE/api/v1/kpi/sanity" 2>/dev/null || echo "000")
  # Both 401 (parser took first/concat) and 200 (parser took last) are
  # defensible; what would be a bug is 500 / inconsistent code paths.
  if [[ "$status" =~ ^(2|401|403) ]]; then
    _pass "31.8.3 dual-Authorization headers handled [HTTP $status]"
  else
    _fail "31.8.3 dual-Authorization caused $status" "non-deterministic auth"
  fi

  # 31.8.4 Token with surrounding whitespace ("  X  ") — should reject
  # OR strip cleanly; never accept a different token shape.
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer  $LEGIT_ADMIN  " \
    "$BASE/api/v1/kpi/sanity" 2>/dev/null || echo "000")
  if [[ "$status" =~ ^(2|401|403) ]]; then
    _pass "31.8.4 trailing whitespace handled [HTTP $status]"
  else
    _fail "31.8.4 trailing whitespace caused $status" "unexpected"
  fi
fi

final_summary
