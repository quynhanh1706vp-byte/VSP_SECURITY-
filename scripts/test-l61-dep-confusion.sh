#!/usr/bin/env bash
# scripts/test-l61-dep-confusion.sh — dependency-confusion defence.
#
# Classic attack chain: defender publishes `github.com/vsp/internal-util`
# inside their private Git server. CI fetches via GOPROXY, which falls
# back to public proxy.golang.org. An attacker registers
# `github.com/vsp/internal-util` on the PUBLIC proxy with malicious
# code. CI builds resolve the public version → supply chain compromised.
#
# Defences this level probes:
#
#   1. go.mod's `module` directive is namespaced (e.g.
#      `github.com/vsp/platform`) — generic names like `myapp` are
#      easy to squat.
#   2. GOPROXY / GOSUMCHECK / GOPRIVATE configured in CI so internal
#      paths are NOT fetched from public proxy.
#   3. go.sum present and committed — proves module verification is
#      on.
#   4. No import statements use suspicious typosquat-shaped names
#      (e.g. `kubrnetes` vs `kubernetes`).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 61.1 Module path is namespaced ───────────────────────────────────────

phase_open "61.1 go.mod module path is namespaced"

GOMOD="$ROOT/go.mod"
if [[ ! -r "$GOMOD" ]]; then
  _skip "61.1.0 go.mod present" "no go.mod"
  final_summary; exit 0
fi

MODULE_LINE=$(grep '^module ' "$GOMOD" | head -1)
MODULE_PATH=$(echo "$MODULE_LINE" | awk '{print $2}')

# Namespaced = has a domain prefix (contains a `/` after the first dot
# segment). Examples of GOOD: github.com/vsp/platform, go.uber.org/zap.
# BAD: myapp, internal-util, app.
if echo "$MODULE_PATH" | grep -qE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/'; then
  _pass "61.1.1 module path is namespaced: $MODULE_PATH"
else
  _fail "61.1.1 module path easily squat-able" \
    "module=$MODULE_PATH — use a domain-prefixed path like github.com/<org>/<repo>"
fi

# ── 61.2 go.sum present + committed ──────────────────────────────────────

phase_open "61.2 go.sum module checksum file"

if [[ -r "$ROOT/go.sum" ]]; then
  SUM_LINES=$(wc -l < "$ROOT/go.sum" | tr -d ' ')
  if (( SUM_LINES > 10 )); then
    _pass "61.2.1 go.sum present with $SUM_LINES entries"
  else
    _fail "61.2.1 go.sum suspiciously small" "$SUM_LINES lines — verify checksums are recorded"
  fi
else
  _fail "61.2.1 go.sum absent" \
    "no go.sum — module-integrity verification disabled, any proxy can swap deps"
fi

# ── 61.3 GOPROXY / GOPRIVATE configured in CI ────────────────────────────

phase_open "61.3 GOPRIVATE / GONOSUMCHECK in workflows"

# Look for GOPRIVATE / GONOSUMCHECK / GOPROXY set in workflows. The
# fix shape is `GOPRIVATE=github.com/<org>/*` so go won't try the
# public proxy for internal paths.
WF_DIR="$ROOT/.github/workflows"
if [[ ! -d "$WF_DIR" ]]; then
  _skip "61.3.0 workflow dir" "not present"
else
  PRIVATE_SET=$(grep -rEn 'GOPRIVATE|GONOSUMCHECK|GOPROXY' "$WF_DIR" 2>/dev/null \
    | grep -v '^\s*#' \
    | head -3 || true)
  if [[ -n "$PRIVATE_SET" ]]; then
    _pass "61.3.1 GOPRIVATE/GOPROXY configured in workflow"
  else
    _skip "61.3.1 GOPRIVATE setting" \
      "no GOPRIVATE/GOPROXY in workflow — informational; default proxy.golang.org used"
  fi
fi

# ── 61.4 Internal-namespace imports don't escape the module ──────────────

phase_open "61.4 Imports stay within declared module"

# An import like `github.com/<org>/<repo>/x` must match the module
# path. An import like `github.com/<typo>/<repo>/x` would be a real
# bug (or a typo allowing future squat).
ORG_PREFIX=$(echo "$MODULE_PATH" | cut -d/ -f1-2)

# Build the set of internal-looking imports (prefix matches our org).
SUSPECT=()
while IFS= read -r line; do
  imp=${line##* }
  imp=${imp//\"/}
  # Only consider imports that have our org prefix
  if [[ "$imp" == "$ORG_PREFIX"* ]] && [[ "$imp" != "$MODULE_PATH"* ]]; then
    SUSPECT+=("$imp")
  fi
done < <(grep -rhE '^\s+"[a-z0-9.-]+\.[a-z]{2,}/[^"]+"' \
    --include='*.go' \
    "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
    | grep -v '_test\.go' \
    | head -200)

# Use array length directly instead of piping through grep -c .
# Previous version's pipeline (`printf ... | sort -u | grep -c .` with
# || echo 0 fallback) emitted "0\n0" when SUSPECT was empty, which
# `(( N == 0 ))` parsed as a syntax error and fell through to _fail.
UNIQUE_COUNT=${#SUSPECT[@]}
if [[ "$UNIQUE_COUNT" -gt 0 ]]; then
  # Deduplicate via printf | sort -u (only when array is non-empty).
  UNIQUE_COUNT=$(printf '%s\n' "${SUSPECT[@]}" | sort -u | wc -l | tr -dc '0-9')
fi
UNIQUE_COUNT=${UNIQUE_COUNT:-0}

if [[ "$UNIQUE_COUNT" -eq 0 ]]; then
  _pass "61.4.1 no rogue '$ORG_PREFIX/*' imports outside module $MODULE_PATH"
else
  _fail "61.4.1 import path mismatch in module namespace" \
    "$UNIQUE_COUNT distinct imports look like $ORG_PREFIX/* but don't match $MODULE_PATH"
fi

# ── 61.5 No common typo-squat targets ────────────────────────────────────

phase_open "61.5 No known typo-squat targets imported"

# Curated list of typo-squat domains that have caused incidents.
TYPOSQUATS=(
  'kubrnetes'         # kubernetes
  'reqests'           # requests (python, but Go too)
  'lodash-utils'      # lodash
  'gopkg.in/yaml-v2'  # yaml.v2 (note the dash)
  'colourb'           # color
  'crpyto'            # crypto
)

HIT=""
for ts in "${TYPOSQUATS[@]}"; do
  if grep -rqE "\"[a-z0-9.-]+/$ts" --include='*.go' \
     "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null; then
    HIT="$ts"
    break
  fi
done

if [[ -z "$HIT" ]]; then
  _pass "61.5.1 no imports match curated typo-squat list"
else
  _fail "61.5.1 potential typo-squat import" "$HIT — verify against canonical name"
fi

final_summary
