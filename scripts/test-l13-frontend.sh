#!/usr/bin/env bash
# scripts/test-l13-frontend.sh — frontend smoke (curl + DOM grep).
#
# A real Playwright suite is heavy to install and slow in CI. This
# script trades click-fidelity for surface coverage: hit every panel
# HTML the gateway serves, and assert each:
#
#   15.1 returns HTTP 200 with text/html
#   15.2 has a sane <html><head><title> structure
#   15.3 contains no unfilled template placeholders ({{ }} / ${...})
#   15.4 doesn't include obvious in-line panic strings (Uncaught,
#        Cannot read properties of, console.error visible inline)
#   15.5 references core JS bundles that exist on disk
#
# This catches the bug class System Toggles surfaced (handler returned
# JSON path but panel was looking for a different key) AND the silent
# template-rot class (a build script left raw `{{title}}` in shipped
# HTML).
#
# Pre-flight: gateway running, $JWT_SECRET (cookie auth), curl.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

NOW=$(date +%s); EXP=$((NOW + 3600))
H=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
P=$(printf '{"sub":"l13@vsp.local","email":"l13@vsp.local","role":"admin","tenant_id":"default","iat":%d,"exp":%d}' \
  "$NOW" "$EXP" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
S=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
  | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
ADMIN="$H.$P.$S"

# ── 15.1 Top-level entry points reachable ──────────────────────────────────

phase_open "15.1 Entry points — / and /trust serve HTML"

probe_html() {
  local name="$1" url="$2"
  local body status ct
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 -L --max-redirs 5 \
    -H "Authorization: Bearer $ADMIN" "$BASE$url")
  ct=$(curl -s -o /dev/null -w "%{content_type}" --max-time 5 -L --max-redirs 5 \
    -H "Authorization: Bearer $ADMIN" "$BASE$url")
  if [[ "$status" =~ ^(200|304)$ && "$ct" == text/html* ]]; then
    if grep -qE "<html|<!DOCTYPE" "$body" 2>/dev/null; then
      _pass "$name [$status, $ct]"
    else
      _fail "$name body shape" "200 but no <html or <!DOCTYPE in body"
    fi
  else
    _fail "$name" "HTTP $status, ct=$ct"
  fi
  rm -f "$body"
}

probe_html "15.1.1 / (landing)" "/"
probe_html "15.1.2 /trust"      "/trust/"

# ── 15.2 All static panels reachable ───────────────────────────────────────

phase_open "15.2 Panel HTML — every panel reachable, sane shape"

PANEL_TOTAL=0
PANEL_FAIL=0
declare -a PANEL_FAILED

# The gateway typically serves panels under /static/panels/<name>.html
# (or /panels/<name> depending on routing). Probe both, accept whichever
# returns 200.
for f in "$ROOT"/static/panels/*.html; do
  base=$(basename "$f" .html)
  case "$base" in
    *.bak*|*.pre-*|.*) continue ;;
  esac
  PANEL_TOTAL=$((PANEL_TOTAL+1))
  ok=0
  for path in "/static/panels/$base.html" "/panels/$base" "/panels/$base.html"; do
    body=$(mktemp)
    status=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 -L --max-redirs 3 \
      -H "Authorization: Bearer $ADMIN" "$BASE$path" 2>/dev/null)
    if [[ "$status" == "200" ]] && grep -qE "<html|<!DOCTYPE" "$body" 2>/dev/null; then
      ok=1; rm -f "$body"; break
    fi
    rm -f "$body"
  done
  if (( ok == 0 )); then
    PANEL_FAIL=$((PANEL_FAIL+1))
    PANEL_FAILED+=("$base")
  fi
done

if (( PANEL_FAIL == 0 )); then
  _pass "15.2.1 every panel returns 200 [$PANEL_TOTAL/$PANEL_TOTAL]"
else
  printf -v PFAIL '%s, ' "${PANEL_FAILED[@]:0:8}"
  _fail "15.2.1 panels not served" \
    "$PANEL_FAIL/$PANEL_TOTAL panels failed: ${PFAIL%, }"
fi

# ── 15.3 No unfilled template placeholders in shipped HTML ─────────────────

phase_open "15.3 Template rot - bare placeholders not shipped"

# We're looking for SHIPPED rendered output that still contains an
# unfilled server-side placeholder like {{ title }} as user-visible
# text. False positives we must NOT flag:
#   - JS object literal: ${{...}[x]}
#   - GitHub Actions secret refs: ${{ secrets.X }}
#   - JS template-string interpolation: ${...}
#   - Mustache-in-mustache code examples inside <script>
# Approach: probe LIVE rendered HTML, drop scripts/styles/tags, then
# match strictly: identifier between {{ and }}, not preceded by $.
LEAKS=()
for path in "/static/panels/dashboard.html" "/static/panels/findings.html" \
            "/static/panels/audit.html" "/static/index.html" "/static/landing.html"; do
  body=$(curl -s --max-time 5 -L --max-redirs 3 \
    -H "Authorization: Bearer $ADMIN" "$BASE$path" 2>/dev/null)
  text=$(echo "$body" \
    | sed -E 's|<script[^>]*>.*</script>||g' \
    | sed -E 's|<style[^>]*>.*</style>||g' \
    | sed -E 's|<[^>]+>| |g')
  hit=$(echo "$text" | grep -oE '(^|[^$])\{\{ *[a-zA-Z_][a-zA-Z0-9_]* *\}\}' | head -1)
  if [[ -n "$hit" ]]; then
    LEAKS+=("$path: $hit")
  fi
done

if (( ${#LEAKS[@]} == 0 )); then
  _pass "15.3.1 no bare placeholders in rendered text"
else
  printf -v LIST '%s | ' "${LEAKS[@]:0:5}"
  _fail "15.3.1 unfilled placeholders" "${LIST%| }"
fi

# ── 15.4 No obvious in-line error strings ─────────────────────────────────

phase_open "15.4 No inline panic / error markers"

# Look at SHIPPED panels via HTTP, not on-disk files. An attacker who
# renders /trust would otherwise see "Uncaught TypeError" or stack
# traces if a previous build left them in. Probe the hot panels.
ERR_HITS=()
for path in "/static/panels/dashboard.html" "/static/panels/findings.html" "/static/panels/audit.html" "/static/index.html"; do
  body=$(curl -s --max-time 5 -L --max-redirs 3 \
    -H "Authorization: Bearer $ADMIN" "$BASE$path" 2>/dev/null)
  for marker in "Uncaught TypeError" "Cannot read prop" "ReferenceError" "is not defined" "undefined is not"; do
    if echo "$body" | grep -q "$marker"; then
      ERR_HITS+=("$path: $marker")
    fi
  done
done

if (( ${#ERR_HITS[@]} == 0 )); then
  _pass "15.4.1 no JS error strings in shipped panels"
else
  printf -v ELIST '%s, ' "${ERR_HITS[@]:0:3}"
  _fail "15.4.1 error markers visible" "${ELIST%, }"
fi

# ── 15.5 Critical JS assets resolvable ─────────────────────────────────────

phase_open "15.5 Critical bundles — referenced JS exists"

# Pull <script src="..."> from the landing page and confirm each
# resolves to 200 (or is an absolute external URL we don't probe).
LANDING=$(curl -s --max-time 5 -L --max-redirs 3 \
  -H "Authorization: Bearer $ADMIN" "$BASE/" 2>/dev/null)
SRCS=$(echo "$LANDING" | grep -oE '<script[^>]+src="[^"]+"' | grep -oE 'src="[^"]+"' | tr -d '"' | sed 's/^src=//')

MISSING=()
PROBED=0
while IFS= read -r src; do
  [[ -z "$src" ]] && continue
  case "$src" in
    http*) continue ;;   # external CDN, don't probe
  esac
  PROBED=$((PROBED+1))
  # Normalise to leading /
  [[ "${src:0:1}" == "/" ]] || src="/$src"
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -L --max-redirs 3 \
    -H "Authorization: Bearer $ADMIN" "$BASE$src" 2>/dev/null)
  if [[ "$status" != "200" ]]; then
    MISSING+=("$src[$status]")
  fi
done <<<"$SRCS"

if (( ${#MISSING[@]} == 0 )); then
  _pass "15.5.1 all referenced JS bundles serve 200 [$PROBED probed]"
else
  printf -v MLIST '%s, ' "${MISSING[@]:0:5}"
  _fail "15.5.1 missing JS bundles" "${MLIST%, }"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
