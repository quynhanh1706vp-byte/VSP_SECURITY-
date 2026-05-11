#!/usr/bin/env bash
# scripts/test-l65-oidc-hardening.sh — OIDC SSO callback hardening.
#
# Real-world OIDC client bugs:
#
#   1. `iss` claim from id_token NOT compared exactly against the
#      issuer in the provider's discovery document → attacker with
#      a different IdP gets in via the same client_id.
#   2. JWKS endpoint URL hard-coded → key rotation breaks but no
#      one notices for hours / days.
#   3. `nonce` claim in id_token not verified against the value
#      sent in the auth request → replay window.
#   4. `aud` (audience) accepts any value → tokens for OTHER clients
#      hosted at the same IdP work.
#   5. Token endpoint uses client_secret_post when client_secret_jwt
#      or private_key_jwt is supported (defence-in-depth on secret
#      transit).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# Static-analysis sweep on internal/sso/ + handler.

# ── 65.1 `iss` claim verified exactly against discovery ──────────────────

phase_open "65.1 iss claim verification"

SSO_DIRS=()
for cand in "$ROOT/internal/sso" "$ROOT/internal/auth/sso"; do
  [[ -d "$cand" ]] && SSO_DIRS+=("$cand")
done
# Also scan the handler
[[ -d "$ROOT/internal/api/handler" ]] && SSO_DIRS+=("$ROOT/internal/api/handler")

if (( ${#SSO_DIRS[@]} == 0 )); then
  _skip "65.1.0 SSO source dir" "no internal/sso/ or auth/sso/ found"
  final_summary; exit 0
fi

# Look for code that verifies `iss`. Patterns:
#   claims.Issuer == discoveredIssuer
#   if iss != p.Issuer
#   token.Claims.(*Claims).Issuer
#   VerifyIssuer
HIT=$(grep -rnE 'Issuer\s*==|VerifyIssuer|\.Iss\b\s*[!=]=|"iss"' \
  --include='*.go' "${SSO_DIRS[@]}" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -3 || true)

if [[ -n "$HIT" ]]; then
  _pass "65.1.1 iss-claim verification code present"
else
  _fail "65.1.1 no iss-claim check in SSO code" \
    "issuer not verified — attacker IdP can substitute tokens"
fi

# ── 65.2 JWKS cache + rotation respected ─────────────────────────────────

phase_open "65.2 JWKS rotation"

# JWKS endpoint URL should come from discovery, not be hard-coded.
# Look for `jwks_uri` references or JWKS-fetcher patterns.
JWKS_REF=$(grep -rnE 'jwks_uri|JWKSURL|JWKS\b' \
  --include='*.go' "${SSO_DIRS[@]}" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -3 || true)

if [[ -n "$JWKS_REF" ]]; then
  _pass "65.2.1 JWKS URL referenced (from discovery)"
else
  _skip "65.2.1 JWKS rotation" \
    "no jwks_uri/JWKSURL reference — informational; ensure not hard-coded"
fi

# Hard-coded keys check: a literal `-----BEGIN PUBLIC KEY-----` in
# any .go file (outside test fixtures) is a red flag.
HARDCODED=$(grep -rEn 'BEGIN (RSA |EC )?PUBLIC KEY' \
  --include='*.go' \
  "$ROOT/internal/" 2>/dev/null \
  | grep -v '_test\.go\|\.bak\|testdata/' \
  | head -3 || true)

if [[ -z "$HARDCODED" ]]; then
  _pass "65.2.2 no hard-coded PEM keys in SSO source"
else
  _fail "65.2.2 hard-coded PEM key in source" \
    "$(echo "$HARDCODED" | head -1) — rotation requires source change"
fi

# ── 65.3 nonce verification ─────────────────────────────────────────────

phase_open "65.3 nonce claim verification"

# Look for nonce field handling — should be saved at authz request
# time and verified at callback.
NONCE_GEN=$(grep -rnE '\bnonce\b' \
  --include='*.go' "${SSO_DIRS[@]}" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -3 || true)

if [[ -n "$NONCE_GEN" ]]; then
  _pass "65.3.1 nonce field handled in SSO code"
else
  _fail "65.3.1 no nonce in SSO code" \
    "without nonce verification, id_token replay window is open"
fi

# ── 65.4 audience (aud) check ───────────────────────────────────────────

phase_open "65.4 audience claim verification"

AUD_HIT=$(grep -rnE 'Audience\s*==|VerifyAudience|\.Aud\b\s*[!=]=|"aud"' \
  --include='*.go' "${SSO_DIRS[@]}" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -3 || true)

if [[ -n "$AUD_HIT" ]]; then
  _pass "65.4.1 aud-claim verification code present"
else
  _fail "65.4.1 no aud-claim check" \
    "audience not checked — tokens for other clients at same IdP accepted"
fi

# ── 65.5 state parameter generated cryptographically ────────────────────

phase_open "65.5 state parameter cryptographic source"

# State should come from crypto/rand, not math/rand.
STATE_GEN=$(grep -rnE 'state\s*[:=].*rand\.|CreateLoginState' \
  --include='*.go' "${SSO_DIRS[@]}" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -3 || true)

# Verify the crypto/rand import is present
if grep -rqE 'crypto/rand' --include='*.go' "${SSO_DIRS[@]}" 2>/dev/null; then
  _pass "65.5.1 SSO code imports crypto/rand (likely state source)"
else
  _fail "65.5.1 SSO code doesn't import crypto/rand" \
    "state parameter likely from math/rand — guessable"
fi

# ── 65.6 callback rejects code reuse ────────────────────────────────────

phase_open "65.6 authorization code single-use guard"

# Look for one-time semantics in CreateLoginState / VerifyLoginState
# (the state row should be deleted/expired after first use).
USED_FLAG=$(grep -rnE 'used\b|consumed\b|UPDATE.*login_state|DELETE FROM.*login_state' \
  --include='*.go' "${SSO_DIRS[@]}" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -3 || true)

if [[ -n "$USED_FLAG" ]]; then
  _pass "65.6.1 login_state has used/consumed/delete handling"
else
  _skip "65.6.1 code-reuse guard" \
    "no used/consumed pattern found — verify state is single-use"
fi

final_summary
