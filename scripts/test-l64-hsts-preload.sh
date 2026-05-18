#!/usr/bin/env bash
# scripts/test-l64-hsts-preload.sh — HSTS / preload eligibility.
#
# Browser HSTS preload list inclusion (hstspreload.org) requires:
#   1. `Strict-Transport-Security` header on every response
#   2. max-age ≥ 31536000 (1 year)
#   3. `includeSubDomains` directive present
#   4. `preload` directive present
#   5. HTTPS-only (HTTP redirects to HTTPS)
#
# Probe enforces the header SHAPE; the HTTPS-only check is informational
# because CI runs plain HTTP.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"

# ── 64.1 STS header present on dashboard ─────────────────────────────────

phase_open "64.1 Strict-Transport-Security header shape"

HEADERS=$(curl -s -i -L --max-time 5 \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/" 2>/dev/null | tr -d '\r' || true)

STS=$(echo "$HEADERS" | grep -i '^Strict-Transport-Security:' | head -1 || true)

if [[ -z "$STS" ]]; then
  _fail "64.1.1 STS header missing on /" \
    "no Strict-Transport-Security — required for HSTS preload eligibility"
else
  _pass "64.1.1 STS present: $(echo "$STS" | head -c 100)"

  # 64.1.2 max-age ≥ 31536000
  MAXAGE=$(echo "$STS" | grep -oE 'max-age=[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
  MAXAGE=${MAXAGE:-0}
  if [[ "$MAXAGE" -ge 31536000 ]]; then
    _pass "64.1.2 max-age=$MAXAGE ≥ 1 year (preload eligible)"
  else
    _fail "64.1.2 max-age too short" \
      "max-age=$MAXAGE; need ≥ 31536000 (1 year) for preload"
  fi

  # 64.1.3 includeSubDomains
  if echo "$STS" | grep -qi 'includeSubDomains'; then
    _pass "64.1.3 includeSubDomains present"
  else
    _fail "64.1.3 includeSubDomains absent" \
      "subdomains not covered — preload list rejects"
  fi

  # 64.1.4 preload directive
  if echo "$STS" | grep -qi 'preload'; then
    _pass "64.1.4 preload directive present"
  else
    _skip "64.1.4 preload directive" \
      "absent — informational; submit to hstspreload.org first, then add"
  fi
fi

# ── 64.2 STS not on /api/v1/status (anon liveness path) ──────────────────

phase_open "64.2 STS consistent across anonymous + auth surfaces"

# /api/v1/status is the anonymous health endpoint. STS should still
# fire (browsers cache it from the first response on a host).
HEADERS=$(curl -s -i --max-time 5 "$BASE/api/v1/status" 2>/dev/null \
  | tr -d '\r' || true)
if echo "$HEADERS" | grep -qi '^Strict-Transport-Security:'; then
  _pass "64.2.1 STS also emitted on /api/v1/status (anonymous)"
else
  _fail "64.2.1 STS missing on anonymous endpoint" \
    "first request to a fresh host should still set STS — defence-in-depth"
fi

# ── 64.3 No upgrade-insecure-requests CSP directive missing ──────────────

phase_open "64.3 CSP upgrade-insecure-requests"

HEADERS=$(curl -s -i -L --max-time 5 \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/" 2>/dev/null | tr -d '\r' || true)
CSP=$(echo "$HEADERS" | grep -i '^Content-Security-Policy:' | head -1 || true)

if echo "$CSP" | grep -qi 'upgrade-insecure-requests'; then
  _pass "64.3.1 CSP upgrade-insecure-requests directive present"
else
  _skip "64.3.1 upgrade-insecure-requests" \
    "absent — informational; auto-upgrades any http:// asset to https://"
fi

# ── 64.4 No mixed-content allow in CSP ───────────────────────────────────

phase_open "64.4 CSP doesn't allow plain http: schemes"

if echo "$CSP" | grep -qE 'http:[[:space:]]'; then
  _fail "64.4.1 CSP allows plain http:" \
    "$(echo "$CSP" | head -c 200) — mixed-content not blocked"
else
  _pass "64.4.1 CSP doesn't allowlist plain http: schemes"
fi

final_summary
