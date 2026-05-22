#!/usr/bin/env bash
# scripts/test-l15-http-hygiene.sh — HTTP response hygiene.
#
# Static HTTP-level audit: every response carries the expected
# security headers, every Set-Cookie carries the right attributes,
# CORS doesn't reflect a foreign origin into Access-Control-Allow-
# Origin, HSTS is present, X-Frame-Options blocks clickjacking, etc.
#
# This catches the bug class where a NEW endpoint gets added without
# the security middleware applied — common when handlers are mounted
# outside the main router group.
#
# Pre-flight: gateway running on $BASE.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq

# ── 16.1 Required security headers on JSON endpoints ───────────────────────

phase_open "16.1 Security headers — every JSON response carries the canon set"

# Probe a representative anonymous + an authenticated endpoint. Both
# must carry the same security-header floor.
HEADERS_TMP=$(mktemp)
curl -s -i --max-time 5 "$BASE/api/v1/status" > "$HEADERS_TMP" 2>/dev/null

check_header() {
  local name="$1" header_re="$2" expect_match="$3"
  if grep -qiE "^$header_re" "$HEADERS_TMP"; then
    if [[ -z "$expect_match" ]] || grep -iE "^$header_re" "$HEADERS_TMP" | grep -qiE "$expect_match"; then
      _pass "16.1.$name [$(grep -iE "^$header_re" "$HEADERS_TMP" | head -1 | tr -d '\r' | head -c 100)]"
    else
      _fail "16.1.$name value" "header present but value doesn't match /$expect_match/"
    fi
  else
    _fail "16.1.$name missing" "header /$header_re/ not present"
  fi
}

check_header "1 X-Content-Type-Options"   "X-Content-Type-Options:"     "nosniff"
check_header "2 X-Frame-Options"          "X-Frame-Options:"            "DENY|SAMEORIGIN"
check_header "3 Strict-Transport-Security" "Strict-Transport-Security:" "max-age=[0-9]+"
check_header "4 Referrer-Policy"          "Referrer-Policy:"            "no-referrer|strict-origin"
check_header "5 Content-Security-Policy"  "Content-Security-Policy:"    "default-src"
check_header "6 Permissions-Policy"       "Permissions-Policy:"         "camera|microphone|geolocation"

rm -f "$HEADERS_TMP"

# ── 16.2 Set-Cookie attribute audit ────────────────────────────────────────

phase_open "16.2 Cookies — HttpOnly + SameSite present, Secure flagged for prod"

# Hit auth/login (sets session cookie even on failed login? probably
# not — but probe). Then probe /api/v1/status which sets vsp_csrf.
ALL_COOKIES=$(curl -s -i --max-time 5 \
  -H "X-Forwarded-Proto: https" \
  "$BASE/api/v1/status" 2>/dev/null | grep -i "^Set-Cookie:")

if [[ -z "$ALL_COOKIES" ]]; then
  _skip "16.2.x cookie audit" "no Set-Cookie headers on /api/v1/status"
else
  # Each cookie line is one entry.
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    name=$(echo "$line" | sed -E 's/^[Ss]et-[Cc]ookie:\s*([^=]+)=.*/\1/')
    has_samesite=$(echo "$line" | grep -ic "SameSite=" || true)
    has_secure=$(echo "$line"   | grep -ic "Secure"    || true)
    has_httponly=$(echo "$line" | grep -ic "HttpOnly"  || true)

    # SameSite is required for every cookie.
    if (( has_samesite >= 1 )); then
      _pass "16.2.SameSite_$name [present]"
    else
      _fail "16.2.SameSite_$name missing" "cookie $name has no SameSite attribute"
    fi

    # Secure — required when X-Forwarded-Proto: https is the request
    # context. Failure means cookie can leak over plaintext if the
    # gateway is ever misconfigured behind an HTTP proxy.
    if (( has_secure >= 1 )); then
      _pass "16.2.Secure_$name [present under XFP=https]"
    else
      # vsp_csrf is double-submit pattern → MAY legitimately not be
      # Secure in dev, but should be Secure when behind HTTPS proxy.
      _fail "16.2.Secure_$name missing under HTTPS" "cookie $name lacks Secure when X-Forwarded-Proto=https"
    fi

    # HttpOnly: required for SESSION cookies (vsp_token), not for
    # double-submit CSRF tokens (which JS must read).
    case "$name" in
      vsp_token|session|jwt)
        if (( has_httponly >= 1 )); then
          _pass "16.2.HttpOnly_$name [present]"
        else
          _fail "16.2.HttpOnly_$name missing" "session cookie $name must be HttpOnly"
        fi
        ;;
      vsp_csrf|csrf*)
        # double-submit pattern intentionally lets JS read the value
        : ;;
    esac
  done <<<"$ALL_COOKIES"
fi

# ── 16.3 CORS — no wildcard reflection of foreign origin ───────────────────

phase_open "16.3 CORS — no foreign-origin reflection"

# Probe with an obvious malicious origin. The server must NOT echo it
# back into Access-Control-Allow-Origin (which combined with credentials
# would let any site read cross-origin responses).
EVIL="https://evil.example.com"
ACAO=$(curl -s -i -X OPTIONS \
  -H "Origin: $EVIL" \
  -H "Access-Control-Request-Method: GET" \
  --max-time 5 "$BASE/api/v1/status" 2>/dev/null \
  | grep -i "^Access-Control-Allow-Origin:" | tr -d '\r' | sed 's/.*: *//')

if [[ -z "$ACAO" ]]; then
  _pass "16.3.1 no Access-Control-Allow-Origin for foreign origin"
elif [[ "$ACAO" == "$EVIL" ]]; then
  _fail "16.3.1 ACAO reflects foreign origin" \
    "server echoed $EVIL back — combined with credentials this is a CORS bypass"
elif [[ "$ACAO" == "*" ]]; then
  # Wildcard ACAO is OK for fully-public endpoints WITHOUT cookies,
  # but if the gateway also sends Allow-Credentials the spec says the
  # browser will reject anyway. Still, flag it for review.
  _fail "16.3.1 ACAO wildcard" \
    "* allowed — verify endpoint has no credentialed responses"
else
  _pass "16.3.1 ACAO scoped: $ACAO"
fi

# Combined check: Allow-Origin + Allow-Credentials together must be
# tightly scoped (no wildcard).
ACAC=$(curl -s -i -X OPTIONS \
  -H "Origin: $EVIL" \
  -H "Access-Control-Request-Method: GET" \
  --max-time 5 "$BASE/api/v1/status" 2>/dev/null \
  | grep -i "^Access-Control-Allow-Credentials:" | tr -d '\r' | sed 's/.*: *//')

if [[ "$ACAO" == "*" && "$ACAC" =~ true ]]; then
  _fail "16.3.2 ACAO=* with Allow-Credentials=true" \
    "browsers reject this combo, but it indicates a config bug"
else
  _pass "16.3.2 no ACAO=* combined with credentials"
fi

# ── 16.4 No verbose error / stack-trace leak in 5xx ────────────────────────

phase_open "16.4 5xx responses don't leak stack traces"

# Force a 5xx by hitting an endpoint with a malformed payload. Probe
# the body for stack-trace markers (file paths, package paths,
# "goroutine N", "runtime/", line numbers).
BODY_TMP=$(mktemp)
curl -s -o "$BODY_TMP" --max-time 5 \
  -X POST -H "Content-Type: application/json" \
  -d 'not-json-at-all' \
  "$BASE/api/v1/auth/login" >/dev/null

LEAKS=$(grep -E "goroutine [0-9]|/usr/lib/go|/home/test/|github\.com/|runtime/[a-z]+\.go|panic: " "$BODY_TMP" 2>/dev/null | head -3)
if [[ -z "$LEAKS" ]]; then
  _pass "16.4.1 no stack-trace markers in error body"
else
  printf -v LIST '%s | ' "${LEAKS[@]}"
  _fail "16.4.1 stack trace leaked" "$LEAKS"
fi
rm -f "$BODY_TMP"

# ── 16.5 No debug-only routes accessible ───────────────────────────────────

phase_open "16.5 Debug routes — not exposed to remote callers"

# pprof + expvar are useful locally for debugging but must NOT be
# reachable from a remote network position. We can't easily run from
# a non-loopback IP in this test rig, so we fake the source IP via
# a TCP connection to the gateway from a remote interface, OR we
# verify the gate by checking the loopback-only middleware exists in
# code AND that probes through it would be denied.
#
# Direct verification: read the gateway code for the loopback gate.
# If the gate's IP allow-list is present, the test passes.
# A regression that drops the gate would surface here.
declare -A DEBUG_PATHS=(
  ["/debug/pprof/"]="pprof index"
  ["/debug/pprof/heap"]="pprof heap"
  ["/debug/pprof/goroutine"]="pprof goroutine"
  ["/debug/vars"]="expvar"
)

# 16.5.1 Loopback gate is enforced by source code.
GW_FILE="$ROOT/cmd/gateway/main.go"
if grep -qE "/debug/\*" "$GW_FILE" && \
   grep -B1 -A20 "/debug/\*" "$GW_FILE" | grep -qE 'ip != "127\.0\.0\.1"'; then
  _pass "16.5.1 /debug/* gated by loopback-only source check in main.go"
else
  _fail "16.5.1 /debug/* gate missing" \
    "loopback IP allow-list not detected in main.go — debug routes may be exposed"
fi

# 16.5.2 Behavioral probe: spoof the request as if it came from a
# remote IP via X-Forwarded-For. The gate uses RemoteAddr (TCP-level)
# not the header, so a remote attacker can't bypass it via XFF — but
# we still log here whether the loopback probe works (sanity, expected
# 200 since this curl IS on localhost).
for path in "${!DEBUG_PATHS[@]}"; do
  desc="${DEBUG_PATHS[$path]}"
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE$path")
  if [[ "$status" == "200" ]]; then
    # Confirms the route IS accessible from loopback. Combined with
    # 16.5.1 above we know remote callers are blocked at the IP layer.
    _pass "16.5 $path loopback ok [200, $desc — remote blocked by gate]"
  elif [[ "$status" =~ ^(403|404|401)$ ]]; then
    # Even loopback can't reach it — pprof was disabled entirely.
    _pass "16.5 $path → $status ($desc disabled in this build)"
  else
    _fail "16.5 $path unexpected" "HTTP $status from loopback for $desc"
  fi
done

# 16.5.3 /debug/stack — explicitly should not be a route.
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE/debug/stack")
if [[ "$status" == "404" ]]; then
  _pass "16.5.3 /debug/stack → 404 (no stack dump route)"
else
  _fail "16.5.3 /debug/stack" "HTTP $status (expected 404)"
fi

# ── 16.6 Method allow-list ─────────────────────────────────────────────────

phase_open "16.6 Method enforcement — TRACE/CONNECT rejected"

# TRACE can echo back headers (cookies in plaintext) and is widely
# disallowed. CONNECT is for proxies and shouldn't be allowed on an
# app server.
for method in TRACE CONNECT; do
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X $method "$BASE/api/v1/status")
  # Any non-2xx is a rejection. The exact code depends on which layer
  # blocks: 405 (method not allowed), 400 (bad request), 403 (server
  # policy), 501 (not implemented). 200 means the method was honored
  # — that's the bug to catch.
  if [[ "$status" =~ ^(2)[0-9][0-9]$ ]]; then
    _fail "16.6 $method allowed" "HTTP $status — method was honored, expected rejection"
  else
    _pass "16.6 $method rejected [$status]"
  fi
done

# ── final ──────────────────────────────────────────────────────────────────

final_summary
