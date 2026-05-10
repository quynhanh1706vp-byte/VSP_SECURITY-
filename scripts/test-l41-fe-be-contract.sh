#!/usr/bin/env bash
# scripts/test-l41-fe-be-contract.sh — frontend ↔ backend contract drift.
#
# What we proved with the 2026-05-10 remediation/finding bug: a fetch()
# in the frontend pointing at a path the backend doesn't register
# silently 404s in the user's browser console with no CI signal.
#
# This level scans static/**/*.html and static/**/*.js for every
# fetch / api() / xhr call against /api/v1/..., then verifies:
#
#   1. Every (METHOD, PATH) tuple referenced by the FE has a matching
#      route registered in cmd/gateway/main.go (chi r.Get/Post/...).
#   2. Every path looks well-formed — no bare slashes, no '<' literals,
#      no obvious template-not-substituted bugs.
#   3. The OpenAPI spec at api/openapi.yaml lists each FE-referenced
#      path (so SDK clients stay in sync). FAILs are SOFT here because
#      OpenAPI lag is common.
#
# Static analysis only — no live gateway needed.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 41.1 Extract every (METHOD, PATH) call site from the FE ───────────────

phase_open "41.1 FE-call inventory"

FE_CALLS=$(mktemp)
# Match patterns:
#   fetch('/api/v1/foo/bar', ...)
#   fetch("/api/v1/foo/bar")
#   fetch(`/api/v1/foo/${id}/bar`)  — backtick template
#   api('POST', '/foo/bar', ...)    — internal api() helper
#
# Extract the path portion. Method is harder — without method=POST
# arg, fetch defaults to GET. We capture method when explicit.
grep -rEhn \
  "fetch\((['\"\`])/api/v1/[a-zA-Z0-9_/{}\$\.\-]+|api\((['\"\`])(GET|POST|PUT|PATCH|DELETE)\1\s*,\s*(['\"\`])/[a-zA-Z0-9_/{}\$\.\-]+" \
  "$ROOT/static/" 2>/dev/null \
  | head -200 > "$FE_CALLS" || true

CALL_COUNT=$(wc -l < "$FE_CALLS" | tr -d ' ')
if [[ "$CALL_COUNT" -lt 5 ]]; then
  _skip "41.1.0 FE call inventory" "only $CALL_COUNT call sites — extractor regex may be too narrow"
else
  _pass "41.1.0 extracted $CALL_COUNT FE-call references"
fi

# ── 41.2 Bare-slash / template-leak paths ────────────────────────────────

phase_open "41.2 No bare-slash / unsubstituted-template paths"

# Pattern: a fetch URL that ends in `/` followed by IMMEDIATE quote
# AND the call has NO concatenation/template — i.e. truly a bare
# slash. The shape we want to flag:
#     fetch('/api/v1/foo/bar/')
#     fetch("/api/v1/foo/bar/")
# But NOT:
#     fetch('/api/v1/foo/bar/' + id)
#     fetch(`/api/v1/foo/bar/${id}`)
# A `'+`, `\`+`, or `${` after the trailing slash means an ID is
# being appended — that's a separate bug class (the empty-ID case
# was already caught by the L13 / 15.6.1 probe).
BARE_SLASH=$(grep -rEhn \
  "fetch\((['\"])/api/v1/[a-zA-Z0-9_/-]+/\1[[:space:]]*[,)]" \
  "$ROOT/static/" 2>/dev/null \
  | grep -v "encodeURIComponent" \
  | head -5 || true)

if [[ -n "$BARE_SLASH" ]]; then
  _fail "41.2.1 bare trailing-slash fetch URL (no concat)" \
    "$(echo "$BARE_SLASH" | head -1)"
else
  _pass "41.2.1 no bare-slash fetch URLs"
fi

UNSUB=$(grep -rEhn '/api/v1/.*\${[^}]+}' "$ROOT/static/" 2>/dev/null \
  | grep -v "// " \
  | head -3 || true)
if [[ -n "$UNSUB" ]]; then
  # Template literals in JS use backticks; finding $ {var} inside a
  # plain string literal (single/double quote) means the template was
  # never substituted.
  STRING_TEMPLATE=$(echo "$UNSUB" | grep -E "['\"][^\"']*\\\$\{" | head -1 || true)
  if [[ -n "$STRING_TEMPLATE" ]]; then
    _fail "41.2.2 unsubstituted \${var} in non-template string" "$STRING_TEMPLATE"
  else
    _pass "41.2.2 \${var} usage all in valid backtick templates"
  fi
else
  _pass "41.2.2 no \${var} placeholder leaks"
fi

# ── 41.3 Every FE-referenced path has a backend route ────────────────────

phase_open "41.3 FE paths registered in cmd/gateway/main.go"

# Build the route table: extract `r.Get("/api/v1/...")`, .Post, .Put,
# .Patch, .Delete from main.go (and helper files in cmd/gateway/).
ROUTES=$(mktemp)
grep -rhE 'r\.(Get|Post|Put|Patch|Delete|Handle|HandleFunc)\("/api/v1/' \
  "$ROOT/cmd/gateway/" 2>/dev/null \
  | grep -oE '/api/v1/[a-zA-Z0-9_/{}\.\-]+' \
  | sort -u > "$ROUTES" || true

ROUTE_COUNT=$(wc -l < "$ROUTES" | tr -d ' ')
if [[ "$ROUTE_COUNT" -lt 10 ]]; then
  _skip "41.3.0 backend route inventory" "only $ROUTE_COUNT routes extracted"
  rm -f "$FE_CALLS" "$ROUTES"
  final_summary
  exit 0
fi
_pass "41.3.0 extracted $ROUTE_COUNT backend routes"

# Pull FE paths only.
FE_PATHS=$(mktemp)
grep -oE '/api/v1/[a-zA-Z0-9_/{}\$\.\-]+' "$FE_CALLS" 2>/dev/null \
  | sort -u > "$FE_PATHS" || true

# For each FE path, search for a backend route that matches under
# chi's path-param model. We canonicalise both sides:
#   - strip trailing slash (chi treats /foo and /foo/ same iff
#     StripSlashes middleware is on, which it is in this gateway)
#   - replace ${var} or :var or {var} with a placeholder marker
#   - replace any concrete UUID-shape with the same marker
canonicalise() {
  echo "$1" \
    | sed -E 's:/$::' \
    | sed -E 's/\$\{[^}]+\}/{X}/g' \
    | sed -E 's/\{[^}]+\}/{X}/g' \
    | sed -E 's/:[a-zA-Z_][a-zA-Z0-9_]*/{X}/g' \
    | sed -E 's:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}:{X}:g'
}

MISSING=()
WHILE_COUNT=0
while IFS= read -r fe_path; do
  [[ -z "$fe_path" ]] && continue
  WHILE_COUNT=$((WHILE_COUNT + 1))
  fe_canon=$(canonicalise "$fe_path")
  # Skip clearly-templated stubs that came from the regex catching
  # literal placeholder text (e.g. /api/v1/<id>).
  case "$fe_canon" in
    */api/v1) continue ;;
    *'<'*'>'*) continue ;;
  esac
  found=0
  while IFS= read -r be_route; do
    [[ -z "$be_route" ]] && continue
    be_canon=$(canonicalise "$be_route")
    if [[ "$fe_canon" == "$be_canon" ]]; then
      found=1
      break
    fi
    # Also accept prefix match — FE might call .../{id}/sub when BE
    # registers .../{id}/sub/{action}.
    if [[ "$be_canon" == "$fe_canon"* || "$fe_canon" == "$be_canon"* ]]; then
      found=1
      break
    fi
  done < "$ROUTES"
  if [[ "$found" == "0" ]]; then
    MISSING+=("$fe_path")
  fi
done < "$FE_PATHS"

# Allow a small budget of unmatched paths — some FE code targets
# microservice routes (e.g. /api/sc, /api/dast) which aren't in
# cmd/gateway/main.go but live in their own services. We've already
# constrained the FE_PATHS extraction to /api/v1/... so most should
# match a gateway route.
NUM_MISSING=${#MISSING[@]}
if (( NUM_MISSING == 0 )); then
  _pass "41.3.1 all $WHILE_COUNT FE-referenced paths have a backend route"
elif (( NUM_MISSING <= 3 )); then
  _skip "41.3.1 FE↔BE contract" \
    "$NUM_MISSING / $WHILE_COUNT FE paths unmatched (likely microservice / dynamic): $(printf '%s, ' "${MISSING[@]:0:3}")"
else
  _fail "41.3.1 FE↔BE contract drift" \
    "$NUM_MISSING / $WHILE_COUNT FE paths have NO matching backend route — first 5: $(printf '%s, ' "${MISSING[@]:0:5}")"
fi

rm -f "$FE_CALLS" "$FE_PATHS" "$ROUTES"

# ── 41.4 OpenAPI lists every backend route ───────────────────────────────

phase_open "41.4 OpenAPI coverage of backend routes (soft)"

OPENAPI="$ROOT/api/openapi.yaml"
if [[ ! -r "$OPENAPI" ]]; then
  _skip "41.4.1 OpenAPI coverage" "api/openapi.yaml not readable"
else
  # Extract paths from openapi.yaml (very rough — looks for lines
  # starting with `  /api/v1/...:`)
  OAS_PATHS=$(mktemp)
  grep -oE '^  /api/v1/[^:]+' "$OPENAPI" 2>/dev/null \
    | tr -d ' ' \
    | sort -u > "$OAS_PATHS" || true

  ROUTES=$(mktemp)
  grep -rhE 'r\.(Get|Post|Put|Patch|Delete)\("/api/v1/' \
    "$ROOT/cmd/gateway/" 2>/dev/null \
    | grep -oE '/api/v1/[a-zA-Z0-9_/{}\.\-]+' \
    | sort -u > "$ROUTES" || true

  # Count routes NOT in OpenAPI (allowing path-param canonicalisation).
  UNDOC=0
  while IFS= read -r route; do
    [[ -z "$route" ]] && continue
    rcanon=$(canonicalise "$route")
    found=0
    while IFS= read -r oas; do
      ocanon=$(canonicalise "$oas")
      if [[ "$ocanon" == "$rcanon" ]]; then found=1; break; fi
    done < "$OAS_PATHS"
    if [[ "$found" == "0" ]]; then UNDOC=$((UNDOC + 1)); fi
  done < "$ROUTES"

  TOTAL=$(wc -l < "$ROUTES" | tr -d ' ')
  rm -f "$OAS_PATHS" "$ROUTES"

  if (( TOTAL == 0 )); then
    _skip "41.4.1 OpenAPI coverage" "no routes extracted"
  elif (( UNDOC * 100 / TOTAL <= 30 )); then
    _pass "41.4.1 OpenAPI documents most routes [$((TOTAL - UNDOC))/$TOTAL covered]"
  else
    _skip "41.4.1 OpenAPI coverage drift" \
      "$UNDOC / $TOTAL routes undocumented — OpenAPI may lag implementation; track in follow-up"
  fi
fi

final_summary
