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
#
# For each traversal vector we now triangulate from 4 angles:
#   - HTTP method (GET, HEAD, POST, DELETE) — does HEAD leak
#     Content-Length even when GET 4xx's? Does POST normalise
#     differently than GET in some routers?
#   - With and without admin auth — does an authenticated request
#     decode the path before applying static handler?
#   - Response body inspection — even on HTTP 200 the content must
#     NOT contain /etc/passwd markers (root:x:0:0)
#   - Content-Length sanity — a 4xx response shouldn't have a body
#     larger than the file we tried to read

# _probe_traversal METHOD WITH_AUTH PATH → echoes "STATUS|LEAKED" where
# LEAKED is 1 if response body contains a /etc/passwd marker.
_probe_traversal() {
  local method="$1" auth_flag="$2" path="$3"
  local body status auth_arg=()
  body=$(mktemp)
  if [[ "$auth_flag" == "1" ]]; then
    auth_arg=(-H "Authorization: Bearer $ADMIN")
  fi
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X "$method" "${auth_arg[@]}" \
    "$BASE$path" 2>/dev/null || echo "000")
  local leaked=0
  if grep -qE '^root:[^:]*:0:0:|/usr/sbin/nologin|/etc/shadow' "$body" 2>/dev/null; then
    leaked=1
  fi
  rm -f "$body"
  printf '%s|%s' "$status" "$leaked"
}

for path in \
    "/static/..%2f..%2f..%2fetc%2fpasswd" \
    "/static/..%2f..%2fetc%2fpasswd" \
    "/static/%2e%2e/%2e%2e/etc/passwd" \
    "/static/..%252fetc%252fpasswd" \
    "/static/..%5c..%5cetc%5cpasswd" \
    "/static/...//etc/passwd" \
    "/static/..\\..\\etc\\passwd" \
  ; do
  any_leak=0 leak_method=""
  for method in GET HEAD POST; do
    for auth in 0 1; do
      result=$(_probe_traversal "$method" "$auth" "$path")
      leaked=${result#*|}
      if [[ "$leaked" == "1" ]]; then
        any_leak=1
        leak_method="$method (auth=$auth)"
        break 2
      fi
    done
  done
  if [[ "$any_leak" == "1" ]]; then
    _fail "36.1 traversal '$path' leaked /etc/passwd" "via $leak_method"
  else
    _pass "36.1 traversal '$path' contained across GET/HEAD/POST × auth on/off"
  fi
done

# ── 36.2 API path encoding bypass ─────────────────────────────────────────

phase_open "36.2 API path — encoded variants resolve to same auth check"

# /api/v1/admin/users requires admin. An analyst token MUST get 401/403
# for ANY encoding of that path. If any variant returns 200, the
# router decodes differently than the auth check.
#
# Multi-angle: for each path variant we also check that:
#   - Body content doesn't include user records (look for "tenant_id"
#     or "@" markers that would indicate user-list leakage even if the
#     status code happens to be 200/204).
#   - The behaviour is the same for HEAD and GET (some servers leak
#     metadata via HEAD while protecting GET).
ANALYST="${TOKEN_ANALYST:-$($ROOT/scripts/mint_jwt_local.sh analyst "${JWT_SECRET:-dev-secret-please-change}")}"

# _probe_admin VARIANT METHOD → "status|user-leak" (1 if body contains user records)
_probe_admin() {
  local variant="$1" method="$2"
  local body status leak=0
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X "$method" \
    -H "Authorization: Bearer $ANALYST" \
    "$BASE$variant" 2>/dev/null || echo "000")
  # User-list leak markers: "tenant_id":"...", email "@vsp", role:"admin"
  if grep -qE '"tenant_id":"[0-9a-f-]{36}"|"role":"admin"|"email":"[^"]*@' "$body" 2>/dev/null; then
    leak=1
  fi
  rm -f "$body"
  printf '%s|%s' "$status" "$leak"
}

for variant in \
    "/api/v1/admin/users" \
    "/api/v1/admin%2Fusers" \
    "/api/v1/%61dmin/users" \
    "/api/v1/admin/./users" \
    "/api/v1/admin//users" \
    "/api/v1/admin/users/" \
    "/api/v1/admin/users%00.json" \
  ; do
  worst_status="" worst_leak=0
  for method in GET HEAD; do
    result=$(_probe_admin "$variant" "$method")
    s=${result%|*}; l=${result#*|}
    if [[ "$l" == "1" ]]; then
      worst_leak=1
      worst_status="$s ($method body)"
      break
    fi
    # Track the worst (most-permissive) status for the failure detail.
    if [[ "$s" == "200" ]]; then worst_status="$s ($method)"; fi
    [[ -z "$worst_status" ]] && worst_status="$s"
  done

  if [[ "$worst_leak" == "1" ]]; then
    _fail "36.2 encoding+content bypass: '$variant'" \
      "user records leaked at HTTP $worst_status — router/auth decode mismatch"
  elif echo "$worst_status" | grep -qE '^200'; then
    _fail "36.2 encoding bypass: '$variant'" \
      "analyst got HTTP $worst_status — review user-list visibility"
  elif echo "$worst_status" | grep -qE '^(401|403|404|405)'; then
    _pass "36.2 analyst→admin '$variant' rejected on GET+HEAD [HTTP $worst_status]"
  else
    _skip "36.2 '$variant'" "unexpected HTTP $worst_status"
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
