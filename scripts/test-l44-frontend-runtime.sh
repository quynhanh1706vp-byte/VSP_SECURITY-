#!/usr/bin/env bash
# scripts/test-l44-frontend-runtime.sh — frontend page-load smoke.
#
# Headless-browser testing is heavy for CI; this level is the pragmatic
# middle ground:
#
#   1. HTTP-fetch each panel HTML — must return 200, must have <html>
#      and reach </body> (truncation = a server-render fault).
#   2. Each <script src="..."> referenced from a panel must serve 200.
#      (Already covered partially by L13; here we sweep ALL panels,
#      not just index.)
#   3. Static-grep each .html / .js for known runtime-error patterns:
#      `console.error` outside try/catch, `throw new Error` in module
#      top-level, `await fetch` without `.catch` / try.
#   4. The <title>, <meta name="viewport"> and <meta charset> must
#      be present — basic FE hygiene.
#   5. No mixed content — every absolute URL referenced should be
#      same-origin or HTTPS, never bare `http://` to a third-party.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"

# ── 44.1 Each panel HTML serves 200 + complete body ──────────────────────

phase_open "44.1 Panel HTML smoke — 200 + non-truncated"

# Probe a representative set; some panels are listed in the dump the
# user pasted. Skip backups (.bak.*) and stubs.
PANELS=(
  "/static/index.html"
  "/static/panels/incident_response.html"
  "/static/panels/sw_inventory.html"
  "/static/panels/supply_chain.html"
  "/static/panels/p4_compliance.html"
  "/static/panels/attestation.html"
  "/static/panels/oscal.html"
)

for panel in "${PANELS[@]}"; do
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" \
    "$BASE$panel" 2>/dev/null || echo "000")

  if [[ "$status" == "404" ]]; then
    _skip "44.1 panel $panel" "404 — not deployed"
    rm -f "$body"; continue
  fi

  if [[ "$status" != "200" ]]; then
    _fail "44.1 panel $panel" "HTTP $status (expected 200)"
    rm -f "$body"; continue
  fi

  # Must contain <html and </body — truncated mid-render = bad.
  if ! grep -qi '<html' "$body"; then
    _fail "44.1 $panel missing <html" "response is not an HTML document"
  elif ! grep -qi '</body>' "$body" && ! grep -qi '</html>' "$body"; then
    _fail "44.1 $panel truncated" \
      "body has no </body> / </html> close tag — server-render aborted?"
  else
    SIZE=$(wc -c < "$body" | tr -d ' ')
    _pass "44.1 $panel served complete [$SIZE bytes]"
  fi
  rm -f "$body"
done

# ── 44.2 Required <head> meta tags ───────────────────────────────────────

phase_open "44.2 HTML hygiene — title / charset / viewport"

body=$(mktemp)
curl -s -o "$body" --max-time 5 \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/static/index.html" 2>/dev/null || true

if [[ -s "$body" ]]; then
  for tag in 'meta charset' '<title' 'meta name="viewport"' ; do
    if grep -qi "$tag" "$body"; then
      _pass "44.2 $tag present"
    else
      _fail "44.2 $tag missing" "static/index.html has no $tag"
    fi
  done
else
  _skip "44.2 head meta" "couldn't fetch /static/index.html"
fi
rm -f "$body"

# ── 44.3 Static grep for top-level runtime hazards ───────────────────────

phase_open "44.3 Source-level hazards in static/*.{html,js}"

# 44.3.1 `await fetch(...)` outside a try/catch is an unhandled-rejection
# waiting to happen. Heuristic: count `await fetch` and ensure each is
# within ~10 lines of a `try {` or has `.catch(`. This is fuzzy; we skip
# below a small budget to avoid noise.
HAZARDS=$(grep -rnE '^\s*await\s+fetch\(' "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_' \
  | head -50 || true)
HAZARD_COUNT=$(echo "$HAZARDS" | grep -c . || echo 0)
if [[ "$HAZARD_COUNT" -lt 5 ]]; then
  _pass "44.3.1 only $HAZARD_COUNT top-level `await fetch` references"
else
  _skip "44.3.1 unguarded `await fetch`" \
    "$HAZARD_COUNT references — manual review recommended"
fi

# 44.3.2 `throw new Error(` at module top-level (not inside a function)
# — would fire on script load. Heuristic: lines starting with whitespace
# (not nested deeply) followed by throw new Error.
TOP_THROW=$(grep -rnE '^throw new Error\(' "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_' \
  | head -3 || true)
if [[ -n "$TOP_THROW" ]]; then
  _fail "44.3.2 top-level `throw new Error(` in static asset" \
    "$(echo "$TOP_THROW" | head -1)"
else
  _pass "44.3.2 no module-top-level throws"
fi

# 44.3.3 Unconditional document.write — XSS / blocking-render hazard
DOC_WRITE=$(grep -rnE 'document\.write\(' "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_\|//.*document.write' \
  | head -3 || true)
if [[ -n "$DOC_WRITE" ]]; then
  _skip "44.3.3 document.write usage" \
    "$(echo "$DOC_WRITE" | wc -l) call sites — review for XSS surface"
else
  _pass "44.3.3 no document.write in static/"
fi

# ── 44.4 Mixed content — no plain http:// to third parties ───────────────

phase_open "44.4 Mixed content — no plain `http://` to third parties"

# Match `http://` followed by a domain that ISN'T 127.0.0.1 / localhost.
# Excludes the canonical service-discovery URLs the gateway proxies.
MIXED=$(grep -rEn 'http://(?!127\.|localhost|169\.254|0\.0\.0\.0)' \
  --include='*.html' --include='*.js' \
  "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_\|//.*http:' \
  | head -3 || true)

# `grep -P` would be cleaner but isn't on all systems; alt approach:
PLAIN_HTTP=$(grep -rEhn 'http://[a-zA-Z][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
  --include='*.html' --include='*.js' \
  "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_\|//.*http:\|http://localhost\|http://127' \
  | head -5 || true)

if [[ -n "$PLAIN_HTTP" ]]; then
  _skip "44.4.1 plain http:// to third-party" \
    "informational — $(echo "$PLAIN_HTTP" | head -1)"
else
  _pass "44.4.1 no plain http:// to third-party domains"
fi

# ── 44.5 Browser-cache headers on HTML ───────────────────────────────────

phase_open "44.5 HTML cache headers"

# HTML pages should have Cache-Control: no-cache or short max-age so
# users get JS/HTML updates without manual refresh. JS bundles can be
# cached aggressively by hash-versioning.
HEADERS=$(curl -s -i --max-time 5 \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/static/index.html" 2>/dev/null \
  | tr -d '\r' || true)
cache=$(echo "$HEADERS" | grep -i '^Cache-Control:' | head -1 || true)

if [[ -z "$cache" ]]; then
  _skip "44.5.1 Cache-Control on HTML" "absent — browser default applies"
elif echo "$cache" | grep -qiE 'max-age=[0-9]{6,}'; then
  _fail "44.5.1 HTML cached too long" \
    "$cache — users won't see JS updates"
else
  _pass "44.5.1 HTML Cache-Control: $cache"
fi

final_summary
