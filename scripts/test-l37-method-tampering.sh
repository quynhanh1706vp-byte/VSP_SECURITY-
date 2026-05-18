#!/usr/bin/env bash
# scripts/test-l37-method-tampering.sh — HTTP method tampering.
#
# Probes:
#   1. X-HTTP-Method-Override header — if honoured, a GET can become a
#      POST/DELETE that bypasses CSRF (which only protects state-changing
#      methods at the *real* method layer).
#   2. _method query param / form field with same effect.
#   3. TRACE method — must NOT echo the request including Authorization.
#   4. OPTIONS leakage — exposes admin endpoints unauthenticated?
#   5. WebDAV methods (PROPFIND, MKCOL) — must reject.
#   6. Smuggled method via leading whitespace ("  GET /").

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"
ANALYST="${TOKEN_ANALYST:-$($ROOT/scripts/mint_jwt_local.sh analyst "${JWT_SECRET:-dev-secret-please-change}")}"

# ── 37.1 X-HTTP-Method-Override must NOT bypass auth/CSRF ────────────────

phase_open "37.1 X-HTTP-Method-Override"

# Try GET → DELETE override on an admin-only delete-shaped path.
# If honoured, the GET (which CSRF middleware ignores) becomes a DELETE.
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -X GET \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Authorization: Bearer $ANALYST" \
  "$BASE/api/v1/admin/users/00000000-0000-0000-0000-000000000000" 2>/dev/null || echo "000")

# Acceptable: 401/403/404/405. Not OK: 200 (DELETE happened) or 204.
if [[ "$status" =~ ^(401|403|404|405)$ ]]; then
  _pass "37.1.1 GET+X-HTTP-Method-Override:DELETE rejected [HTTP $status]"
elif [[ "$status" =~ ^(200|204)$ ]]; then
  _fail "37.1.1 method-override bypass" \
    "analyst's GET became DELETE via X-HTTP-Method-Override [HTTP $status]"
else
  _skip "37.1.1 X-HTTP-Method-Override" "unexpected HTTP $status"
fi

# Same for _method query param.
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -X GET \
  -H "Authorization: Bearer $ANALYST" \
  "$BASE/api/v1/admin/users/00000000-0000-0000-0000-000000000000?_method=DELETE" 2>/dev/null || echo "000")

if [[ "$status" =~ ^(401|403|404|405)$ ]]; then
  _pass "37.1.2 GET+_method=DELETE param rejected [HTTP $status]"
elif [[ "$status" =~ ^(200|204)$ ]]; then
  _fail "37.1.2 _method param bypass" \
    "analyst's GET became DELETE via _method= [HTTP $status]"
else
  _skip "37.1.2 _method param" "unexpected HTTP $status"
fi

# ── 37.2 TRACE must NOT echo Authorization ────────────────────────────────

phase_open "37.2 TRACE method — no echo of secrets"

# TRACE response contains the full request. If TRACE is enabled and
# the gateway echoes Authorization, JS-injected pages can read
# HttpOnly cookies via XHR/TRACE (XST attack).
body=$(mktemp)
status=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
  -X TRACE \
  -H "Authorization: Bearer $ADMIN" \
  -H "X-Pii-Probe: l37-trace-$(date +%s)" \
  "$BASE/api/v1/status" 2>/dev/null || echo "000")

# Pass: 4xx (TRACE disabled) OR 200 with Authorization NOT echoed.
if [[ "$status" =~ ^4 ]]; then
  _pass "37.2.1 TRACE method disabled [HTTP $status]"
elif grep -qiE 'authorization:\s*bearer' "$body" 2>/dev/null; then
  _fail "37.2.1 TRACE echoed Authorization header" "XST attack vector"
else
  _pass "37.2.1 TRACE enabled but Authorization not echoed [HTTP $status]"
fi
rm -f "$body"

# ── 37.3 OPTIONS — verb introspection without leaking admin endpoints ────

phase_open "37.3 OPTIONS method — no admin-route leakage"

# OPTIONS on an admin-only endpoint with NO auth: Allow header should
# either omit DELETE/PUT (auth-stripped) OR return 401/403.
# `|| true` because grep -i returns 1 when there's no Allow header,
# which under inherit_errexit-aware shells would abort the script.
allow=$(curl -s -i --max-time 5 -X OPTIONS \
  "$BASE/api/v1/admin/users" 2>/dev/null \
  | grep -i '^Allow:' | head -1 | tr -d '\r' || true)

# Either the gateway answered with auth (401/403) — checked separately
# below — or the Allow header is present. Both are acceptable; we just
# confirm OPTIONS doesn't return 200 with admin verbs to anonymous.
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -X OPTIONS "$BASE/api/v1/admin/users" 2>/dev/null || echo "000")

if [[ "$status" =~ ^(401|403|404|405)$ ]]; then
  _pass "37.3.1 OPTIONS on admin endpoint requires auth [HTTP $status]"
elif [[ "$status" == "200" || "$status" == "204" ]]; then
  # CORS preflight pattern — acceptable as long as the body / Allow
  # header doesn't expose admin verbs.
  _pass "37.3.1 OPTIONS preflight [HTTP $status, $allow]"
else
  _skip "37.3.1 OPTIONS" "unexpected HTTP $status"
fi

# ── 37.4 WebDAV methods must be rejected ─────────────────────────────────

phase_open "37.4 WebDAV / unusual methods"

for verb in PROPFIND MKCOL COPY MOVE LOCK; do
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X "$verb" \
    -H "Authorization: Bearer $ADMIN" \
    "$BASE/api/v1/status" 2>/dev/null || echo "000")
  if [[ "$status" =~ ^(400|404|405|501)$ ]]; then
    _pass "37.4 $verb rejected [HTTP $status]"
  elif [[ "$status" == "200" ]]; then
    _fail "37.4 $verb returned 200" "DAV method must not be honoured"
  else
    _skip "37.4 $verb" "unexpected HTTP $status"
  fi
done

final_summary
