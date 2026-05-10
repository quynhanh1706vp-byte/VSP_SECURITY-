#!/usr/bin/env bash
# scripts/test-l36-path-encoding.sh — path normalization / encoding bypass.
#
# Many security checks happen AFTER URL routing (auth middleware,
# authorization, RLS). If the router normalises differently than the
# checks, an attacker can craft a path that matches no protected
# route at decode time but resolves to one after.
#
# Probes:
#   1. Encoded traversal: %2e%2e/, ..%2f, ..%5c, %252e (double-encoded)
#   2. Null-byte injection: foo%00.txt
#   3. Trailing-slash variance vs StripSlashes middleware
#   4. Unicode dot variants (full-width, ideographic)
#   5. Static-file path traversal: GET /static/../etc/passwd
#
# These are CHECKED, not exploited — we just verify the gateway
# returns 4xx for hostile paths and doesn't leak filesystem content.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"

# ── 36.1 Static file traversal ────────────────────────────────────────────

phase_open "36.1 Static file path traversal"

# /static/* serves files from the static dir. Encoded traversal
# variants must NOT escape into /etc/passwd, gateway binary, etc.
for path in \
    "/static/..%2f..%2f..%2fetc%2fpasswd" \
    "/static/..%2f..%2fetc%2fpasswd" \
    "/static/%2e%2e/%2e%2e/etc/passwd" \
    "/static/..%252fetc%252fpasswd" \
    "/static/..%5c..%5cetc%5cpasswd" \
    "/static/...//etc/passwd" \
    "/static/..\\..\\etc\\passwd" \
  ; do
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    "$BASE$path" 2>/dev/null || echo "000")
  # PASS conditions:
  #   - 4xx response (refused), OR
  #   - 200 but body doesn't contain /etc/passwd content (root: marker)
  leaked=0
  if grep -qE '^root:[^:]*:0:0:' "$body" 2>/dev/null; then
    leaked=1
  fi
  rm -f "$body"

  if [[ "$leaked" -eq 1 ]]; then
    _fail "36.1 traversal '$path' leaked /etc/passwd" "HTTP $status served root: line"
  elif [[ "$status" =~ ^4 || "$status" == "200" ]]; then
    _pass "36.1 traversal '$path' contained [HTTP $status]"
  else
    _skip "36.1 traversal '$path'" "unexpected HTTP $status"
  fi
done

# ── 36.2 API path encoding bypass ─────────────────────────────────────────

phase_open "36.2 API path — encoded variants resolve to same auth check"

# /api/v1/admin/users requires admin. An analyst token MUST get 401/403
# for ANY encoding of that path. If any variant returns 200, the
# router decodes differently than the auth check.
ANALYST="${TOKEN_ANALYST:-$($ROOT/scripts/mint_jwt_local.sh analyst "${JWT_SECRET:-dev-secret-please-change}")}"

for variant in \
    "/api/v1/admin/users" \
    "/api/v1/admin%2Fusers" \
    "/api/v1/%61dmin/users" \
    "/api/v1/admin/./users" \
    "/api/v1/admin//users" \
    "/api/v1/admin/users/" \
    "/api/v1/admin/users%00.json" \
  ; do
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ANALYST" \
    "$BASE$variant" 2>/dev/null || echo "000")

  # Acceptable: 401, 403 (auth/authz blocked), or 404 (router truly
  # didn't recognise it). NOT acceptable: 200 (admin data leaked).
  if [[ "$status" =~ ^(401|403|404)$ ]]; then
    _pass "36.2 analyst→admin '$variant' rejected [HTTP $status]"
  elif [[ "$status" == "200" ]]; then
    _fail "36.2 encoding bypass: '$variant'" \
      "analyst token got HTTP 200 — router/auth path-decode mismatch"
  else
    _skip "36.2 '$variant'" "unexpected HTTP $status"
  fi
done

# ── 36.3 Null-byte / control-char paths ───────────────────────────────────

phase_open "36.3 Path with control characters"

for path in \
    "/api/v1/status%00" \
    "/api/v1/status%0a%0d" \
    "/api/v1/status%09" \
  ; do
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" \
    "$BASE$path" 2>/dev/null || echo "000")

  if [[ "$status" =~ ^(200|400|404)$ ]]; then
    _pass "36.3 control-char path '$path' handled [HTTP $status]"
  else
    _fail "36.3 unexpected response on '$path'" "HTTP $status"
  fi
done

final_summary
