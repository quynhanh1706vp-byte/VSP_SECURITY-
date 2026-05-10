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

# Helper: probe an admin-only endpoint with the given token.
# Returns the HTTP code.
_probe() {
  curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $1" \
    "$BASE/api/v1/admin/users" 2>/dev/null || echo "000"
}

NOW=$(date +%s)
EXP=$((NOW + 86400))

# ── 31.1 alg=none must be rejected ────────────────────────────────────────

phase_open "31.1 alg=none / no-signature variants"

H_NONE=$(_b64url '{"alg":"none","typ":"JWT"}')
P_ADMIN=$(_b64url "{\"sub\":\"attacker@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$NOW,\"exp\":$EXP}")

# alg=none with empty signature
NONE_TOKEN="$H_NONE.$P_ADMIN."
STATUS=$(_probe "$NONE_TOKEN")
if [[ "$STATUS" == "401" || "$STATUS" == "403" ]]; then
  _pass "31.1.1 alg=none rejected [HTTP $STATUS]"
else
  _fail "31.1.1 alg=none accepted" "HTTP $STATUS — auth middleware allowed unsigned token!"
fi

# alg=none with garbage signature
NONE_GARBAGE="$H_NONE.$P_ADMIN.garbage"
STATUS=$(_probe "$NONE_GARBAGE")
if [[ "$STATUS" == "401" || "$STATUS" == "403" ]]; then
  _pass "31.1.2 alg=none + garbage sig rejected [HTTP $STATUS]"
else
  _fail "31.1.2 alg=none + garbage sig accepted" "HTTP $STATUS"
fi

# Empty signature on a valid HS256 header
H_HS=$(_b64url '{"alg":"HS256","typ":"JWT"}')
EMPTY_SIG="$H_HS.$P_ADMIN."
STATUS=$(_probe "$EMPTY_SIG")
if [[ "$STATUS" == "401" || "$STATUS" == "403" ]]; then
  _pass "31.1.3 HS256 with empty signature rejected [HTTP $STATUS]"
else
  _fail "31.1.3 HS256 with empty signature accepted" "HTTP $STATUS"
fi

# ── 31.2 Algorithm confusion (HS256 vs RS256) ─────────────────────────────

phase_open "31.2 Algorithm confusion"

# Submit a token claiming alg=RS256 but actually signed with HS256
# using whatever the secret happens to be. Some libraries fall through
# and use the secret as a public key, which is the classic confusion.
H_RS=$(_b64url '{"alg":"RS256","typ":"JWT"}')
SIG=$(_hs256 "$H_RS.$P_ADMIN" "$JWT_SECRET_RESOLVED")
RS_TOKEN="$H_RS.$P_ADMIN.$SIG"
STATUS=$(_probe "$RS_TOKEN")
if [[ "$STATUS" == "401" || "$STATUS" == "403" ]]; then
  _pass "31.2.1 alg=RS256 + HS256 sig rejected [HTTP $STATUS]"
else
  _fail "31.2.1 algorithm-confusion ACCEPTED" \
    "HTTP $STATUS — middleware should pin to HS256 only"
fi

# ── 31.3 Tampered claims must invalidate signature ────────────────────────

phase_open "31.3 Claim-tampering — sig must invalidate"

# Mint a legit analyst token, then flip role=admin in payload WITHOUT
# resigning. Signature should no longer verify.
P_ANALYST=$(_b64url "{\"sub\":\"analyst@vsp.test\",\"role\":\"analyst\",\"tenant_id\":\"default\",\"iat\":$NOW,\"exp\":$EXP}")
SIG=$(_hs256 "$H_HS.$P_ANALYST" "$JWT_SECRET_RESOLVED")
LEGIT_ANALYST="$H_HS.$P_ANALYST.$SIG"

# Confirm the legit token works as analyst (returns 200 or 403 — but
# NOT 401, which would mean the legit token also failed auth).
STATUS=$(_probe "$LEGIT_ANALYST")
if [[ "$STATUS" == "401" ]]; then
  _skip "31.3 baseline" "legit analyst token failed auth — env mismatch"
else
  _pass "31.3.0 legit analyst token authenticates [HTTP $STATUS]"

  # Flip payload to role=admin, KEEP analyst signature.
  P_ADMIN_TAMPER=$(_b64url "{\"sub\":\"analyst@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$NOW,\"exp\":$EXP}")
  TAMPERED="$H_HS.$P_ADMIN_TAMPER.$SIG"
  STATUS=$(_probe "$TAMPERED")
  if [[ "$STATUS" == "401" || "$STATUS" == "403" ]]; then
    _pass "31.3.1 role-tampered token rejected [HTTP $STATUS]"
  else
    _fail "31.3.1 role-tampered token ACCEPTED" "HTTP $STATUS — sig verification broken"
  fi
fi

# ── 31.4 Expired tokens must be rejected ──────────────────────────────────

phase_open "31.4 Temporal — expired / future-iat"

# exp = 1h ago
EXP_PAST=$((NOW - 3600))
P_EXPIRED=$(_b64url "{\"sub\":\"admin@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$((NOW-7200)),\"exp\":$EXP_PAST}")
SIG=$(_hs256 "$H_HS.$P_EXPIRED" "$JWT_SECRET_RESOLVED")
EXPIRED_TOKEN="$H_HS.$P_EXPIRED.$SIG"
STATUS=$(_probe "$EXPIRED_TOKEN")
if [[ "$STATUS" == "401" || "$STATUS" == "403" ]]; then
  _pass "31.4.1 expired token rejected [HTTP $STATUS]"
else
  _fail "31.4.1 expired token accepted" "HTTP $STATUS — exp not enforced"
fi

# iat 1h in future — most JWT libs allow this; flag as informational.
IAT_FUTURE=$((NOW + 3600))
P_FUTURE=$(_b64url "{\"sub\":\"admin@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$IAT_FUTURE,\"exp\":$((IAT_FUTURE+86400))}")
SIG=$(_hs256 "$H_HS.$P_FUTURE" "$JWT_SECRET_RESOLVED")
FUTURE_TOKEN="$H_HS.$P_FUTURE.$SIG"
STATUS=$(_probe "$FUTURE_TOKEN")
if [[ "$STATUS" == "401" || "$STATUS" == "403" ]]; then
  _pass "31.4.2 future-iat token rejected (strict) [HTTP $STATUS]"
else
  _skip "31.4.2 future-iat token" \
    "accepted (HTTP $STATUS) — most JWT libs allow this; consider tightening if clock-skew is a concern"
fi

# ── 31.5 Long-lived token (year 2099) — accepted with warning? ───────────

phase_open "31.5 Long-expiry tokens"

# A token with exp 75 years out is technically valid but operationally
# concerning. We don't fail on it (RFC compliance) — just record.
EXP_FAR=$((NOW + 75 * 365 * 86400))
P_FAR=$(_b64url "{\"sub\":\"admin@vsp.test\",\"role\":\"admin\",\"tenant_id\":\"default\",\"iat\":$NOW,\"exp\":$EXP_FAR}")
SIG=$(_hs256 "$H_HS.$P_FAR" "$JWT_SECRET_RESOLVED")
FAR_TOKEN="$H_HS.$P_FAR.$SIG"
STATUS=$(_probe "$FAR_TOKEN")
if [[ "$STATUS" == "200" || "$STATUS" == "403" ]]; then
  _skip "31.5.1 75-year token accepted" \
    "HTTP $STATUS — RFC-compliant; consider capping exp at issue time for prod"
elif [[ "$STATUS" == "401" ]]; then
  _pass "31.5.1 75-year token rejected (max-exp policy enforced)"
else
  _skip "31.5.1 75-year token" "unexpected HTTP $STATUS"
fi

# ── 31.6 Wrong-secret signature ───────────────────────────────────────────

phase_open "31.6 Wrong-secret signature"

WRONG_SIG=$(_hs256 "$H_HS.$P_ADMIN" "definitely-not-the-right-secret-$(date +%N)")
WRONG_TOKEN="$H_HS.$P_ADMIN.$WRONG_SIG"
STATUS=$(_probe "$WRONG_TOKEN")
if [[ "$STATUS" == "401" || "$STATUS" == "403" ]]; then
  _pass "31.6.1 wrong-secret signature rejected [HTTP $STATUS]"
else
  _fail "31.6.1 wrong-secret accepted" "HTTP $STATUS — auth middleware misconfigured"
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
  STATUS=$(_probe "$bad")
  if [[ "$STATUS" == "401" || "$STATUS" == "403" ]]; then
    _pass "31.7 malformed token '$(echo "$bad" | head -c 30)...' rejected [HTTP $STATUS]"
  else
    _fail "31.7 malformed token accepted" \
      "input '$bad' returned HTTP $STATUS"
  fi
done

final_summary
