#!/usr/bin/env bash
# scripts/test-l46-fe-xss.sh — FE XSS surface scan.
#
# Static-analysis sweep over static/**/*.{html,js} for the high-yield
# XSS sinks:
#
#   1. innerHTML = expr — where expr can contain user/API content
#   2. outerHTML = expr — same class
#   3. document.write / document.writeln
#   4. eval(...) / new Function(...) / setTimeout(string, ...)
#   5. javascript: URLs (anchor href or location assignment)
#   6. JSON.parse(...) on attacker-controlled string without try
#   7. dangerouslySetInnerHTML (React-style; not in this codebase but
#      flag if any creeps in)
#
# A finding here doesn't necessarily prove XSS — many uses are safe
# (innerHTML with hardcoded template). The probe reports the COUNT
# and the first few risky-looking call sites for review. Threshold-
# based so we fail only on regressions (count grew).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 46.1 innerHTML/outerHTML with concat expressions ─────────────────────

phase_open "46.1 innerHTML/outerHTML with concat expressions"

# Find every `\.innerHTML\s*=\s*` followed by anything containing `+`
# (string concatenation — often user content) or a template literal
# (backticks).
HITS=$(grep -rEn '\.(inner|outer)HTML\s*=\s*[^"`'\'';]*(\+|`)' \
  --include='*.js' --include='*.html' \
  "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_' \
  | grep -vE '//\s*xss-safe|xss-ok' \
  || true)

CONCAT_COUNT=$(echo "$HITS" | grep -c . || echo 0)
CONCAT_COUNT=${CONCAT_COUNT:-0}

# Threshold based on a pre-fix count; treat increases as regression.
# Tightened over time as the codebase migrates to textContent / DOM
# APIs. As of 2026-05-11 the count is in the low hundreds because of
# the legacy panel HTML, so this is a SOFT signal.
# Hard floor: if it crosses a clear runaway (>500) something
# regressed badly.
INNERHTML_BASELINE=400
if (( CONCAT_COUNT > INNERHTML_BASELINE )); then
  _fail "46.1.1 innerHTML+concat call sites above baseline" \
    "$CONCAT_COUNT > $INNERHTML_BASELINE — first: $(echo "$HITS" | head -1)"
else
  _pass "46.1.1 innerHTML+concat call sites at $CONCAT_COUNT / baseline $INNERHTML_BASELINE"
fi

# 46.1.2 — explicit innerHTML = userInput pattern (variable named
# user / input / val / data on the RHS). Tighter signal.
DIRECT=$(grep -rEn '\.(inner|outer)HTML\s*=\s*[a-z]+(Input|Value|Data|Body|Resp|Content|User|Email|Name)\b' \
  --include='*.js' --include='*.html' \
  "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_' \
  | head -3 || true)
if [[ -n "$DIRECT" ]]; then
  _fail "46.1.2 innerHTML = $varName (direct user-input)" \
    "$(echo "$DIRECT" | head -1)"
else
  _pass "46.1.2 no innerHTML = userInput style assignments"
fi

# ── 46.2 eval / new Function / setTimeout-string ─────────────────────────

phase_open "46.2 Dynamic-code sinks (eval / new Function / setTimeout string)"

# eval(...) — almost never legitimate in production JS
EVAL_HITS=$(grep -rEn '\beval\s*\(' \
  --include='*.js' --include='*.html' \
  "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_' \
  | grep -vE '//\s*safe-eval' \
  | head -3 || true)
if [[ -n "$EVAL_HITS" ]]; then
  _fail "46.2.1 eval() call sites" "$(echo "$EVAL_HITS" | head -1)"
else
  _pass "46.2.1 no eval() in static assets"
fi

# new Function(...) — same as eval, just sneakier. Exclude:
#   - .bak files
#   - block-comment lines (start with `*` or `//` after indentation)
#   - vsp-actions.js — documented CSP-compliant inline-handler runner;
#     expressions come from data-vsp-click author markup, not user
#     input, and replacing inline `onclick=` with this gadget is the
#     migration path off CSP 'unsafe-inline'.
NF_HITS=$(grep -rEn '\bnew\s+Function\s*\(' \
  --include='*.js' --include='*.html' \
  "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_' \
  | grep -vE ':\s*(\*|//|<!--)' \
  | grep -v 'vsp-actions\.js' \
  | head -3 || true)
if [[ -n "$NF_HITS" ]]; then
  _fail "46.2.2 new Function() call sites" "$(echo "$NF_HITS" | head -1)"
else
  _pass "46.2.2 no new Function() (comments + vsp-actions.js excluded)"
fi

# setTimeout(string, ...) — only flag when arg 1 is clearly a string
# literal or concat (function-args are fine).
ST_HITS=$(grep -rEn 'setTimeout\s*\(\s*["`'\''][^,)]+["`'\''],' \
  --include='*.js' --include='*.html' \
  "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_' \
  | head -3 || true)
if [[ -n "$ST_HITS" ]]; then
  _fail "46.2.3 setTimeout with string arg" "$(echo "$ST_HITS" | head -1)"
else
  _pass "46.2.3 no setTimeout(string) calls"
fi

# ── 46.3 javascript: URLs ────────────────────────────────────────────────

phase_open "46.3 javascript: URLs in href / location"

# Exclude `javascript:void(0)` and `javascript:;` — these are the
# canonical "anchor that doesn't navigate, click is handled by JS"
# patterns. They carry NO executable payload (void(0) returns
# undefined, `;` is the empty statement), and removing them is a
# huge cosmetic refactor (use buttons instead) without any security
# win. Real XSS surface is `javascript:` + dynamic expression.
JS_URL=$(grep -rEn '(href\s*=\s*["`'\'']?javascript:|location(\.href)?\s*=\s*["`'\'']?javascript:|window\.location\s*=\s*["`'\'']?javascript:)' \
  --include='*.js' --include='*.html' \
  "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_\|//.*javascript:' \
  | grep -vE 'javascript:(void\(0\)|;|\s*$)' \
  | head -3 || true)
if [[ -n "$JS_URL" ]]; then
  _fail "46.3.1 javascript: URL with executable expression" "$(echo "$JS_URL" | head -1)"
else
  _pass "46.3.1 no javascript: URLs (void(0)/empty allowlisted)"
fi

# ── 46.4 document.write — XSS amplifier ──────────────────────────────────

phase_open "46.4 document.write usage"

DW_HITS=$(grep -rEn 'document\.write(ln)?\s*\(' \
  --include='*.js' --include='*.html' \
  "$ROOT/static/" 2>/dev/null \
  | grep -v '\.bak\.\|\.bak_\|//.*document\.write' \
  | head -3 || true)
if [[ -n "$DW_HITS" ]]; then
  _fail "46.4.1 document.write call sites" "$(echo "$DW_HITS" | head -1)"
else
  _pass "46.4.1 no document.write in static assets"
fi

# ── 46.5 dangerouslySetInnerHTML (React canary, shouldn't exist here) ────

phase_open "46.5 dangerouslySetInnerHTML canary"

DSI=$(grep -rEn 'dangerouslySetInnerHTML' \
  --include='*.js' --include='*.html' \
  "$ROOT/static/" 2>/dev/null \
  | head -3 || true)
if [[ -n "$DSI" ]]; then
  _fail "46.5.1 dangerouslySetInnerHTML usage" "$(echo "$DSI" | head -1)"
else
  _pass "46.5.1 no dangerouslySetInnerHTML (codebase isn't React)"
fi

# ── 46.6 Live XSS payload reflection probe ───────────────────────────────

phase_open "46.6 No XSS payload reflection on common endpoints"

# Send an XSS canary in a query param and confirm the response body
# either omits it, encodes it (&lt; / &amp;), or escapes it. The
# canary is unique so we can grep for the raw form.
CANARY="<script>vspXSS$(date +%s%N | sha256sum | head -c 8)</script>"
ENC=$(printf '%s' "$CANARY" | jq -sRr @uri)
ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"

REFLECT=()
for ep in "/api/v1/vsp/findings?q=$ENC" "/api/v1/audit/log?action=$ENC&limit=1"; do
  body=$(mktemp)
  curl -s -o "$body" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" \
    "$BASE$ep" > /dev/null 2>&1 || true
  if grep -qF "$CANARY" "$body" 2>/dev/null; then
    REFLECT+=("$ep — raw <script>...</script> echoed back unencoded")
  fi
  rm -f "$body"
done

if (( ${#REFLECT[@]} == 0 )); then
  _pass "46.6.1 XSS canary not reflected verbatim by sampled endpoints"
else
  _fail "46.6.1 XSS payload reflected unencoded" "${REFLECT[0]}"
fi

final_summary
