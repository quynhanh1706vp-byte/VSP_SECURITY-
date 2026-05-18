#!/usr/bin/env bash
# scripts/test-l20-deps-license.sh — dependency license + supply-chain audit.
#
# Runs go-licenses against every binary entry point and verifies:
#
#   21.1 Every transitive dep has a known SPDX license tag.
#
#   21.2 No GPL / AGPL / SSPL deps that would force open-sourcing
#        the entire product (we ship as a closed-source SaaS).
#
#   21.3 No deps with "unknown" / "non-standard" license — these
#        require manual review before shipping.
#
#   21.4 go.sum integrity — verify go module checksums.
#
# Pre-flight: go + go-licenses installed.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command go

# Locate go-licenses (system PATH or GOPATH/bin).
GOL="$(command -v go-licenses 2>/dev/null || true)"
if [[ -z "$GOL" ]]; then
  GOL="$(go env GOPATH)/bin/go-licenses"
  [[ -x "$GOL" ]] || GOL=""
fi
if [[ -z "$GOL" ]]; then
  printf "%s✗%s go-licenses not installed (go install github.com/google/go-licenses@latest)\n" \
    "$C_RED" "$C_RESET" >&2
  exit 2
fi

cd "$ROOT"

# ── 21.1 License inventory ─────────────────────────────────────────────────

phase_open "21.1 License inventory — every dep has an SPDX tag"

LIC_OUT=$(mktemp)
# csv format: pkg,license_url,license_type
"$GOL" csv ./cmd/gateway/... 2>/dev/null > "$LIC_OUT" || true

if [[ ! -s "$LIC_OUT" ]]; then
  _fail "21.1.0 license scan empty" "go-licenses produced no output (run failed?)"
  rm -f "$LIC_OUT"
  final_summary; exit $?
fi

# Filter out our own packages — they're proprietary by design and
# go-licenses correctly reports them as "unknown" (no LICENSE file).
# Any THIRD-PARTY dep with unknown license is the real concern.
EXTERNAL=$(awk -F',' '$1 !~ /^github\.com\/vsp\/platform/' "$LIC_OUT")
TOTAL=$(echo "$EXTERNAL" | grep -c . | tr -d ' ')
UNKNOWN=$(echo "$EXTERNAL" | awk -F',' '$3 == "" || $3 == "Unknown"' | grep -c . | tr -d ' ')

if (( UNKNOWN == 0 )); then
  _pass "21.1.1 all $TOTAL third-party deps have a recognised license"
else
  EX=$(echo "$EXTERNAL" | awk -F',' '$3 == "" || $3 == "Unknown" {print $1}' | head -3 | tr '\n' ' ')
  _fail "21.1.1 $UNKNOWN/$TOTAL third-party deps with unknown license" "examples: $EX"
fi

# ── 21.2 No copyleft (GPL/AGPL/SSPL) deps ──────────────────────────────────

phase_open "21.2 No copyleft licenses"

# These force any product that distributes them under a strong-copyleft
# regime. For a closed-source SaaS, presence of any of these is a
# release-blocking compliance issue.
COPYLEFT=$(echo "$EXTERNAL" | awk -F',' 'tolower($3) ~ /^(gpl|agpl|sspl|cc-by-nc|wtfpl|unlicense)/ {print $1 " :: " $3}')
if [[ -z "$COPYLEFT" ]]; then
  _pass "21.2.1 no GPL/AGPL/SSPL/CC-BY-NC deps"
else
  HITS=$(echo "$COPYLEFT" | head -5 | tr '\n' '|')
  _fail "21.2.1 strong-copyleft dep present" "$HITS"
fi

# ── 21.3 License allow-list ────────────────────────────────────────────────

phase_open "21.3 License allow-list — only commercially-friendly tags"

# We accept these; flag anything else for manual review.
ALLOW="MIT|Apache-2.0|BSD-2-Clause|BSD-3-Clause|ISC|MPL-2.0|Apache|BSD-2|BSD-3"

OUT_OF_LIST=$(echo "$EXTERNAL" | awk -F',' -v allow="$ALLOW" 'tolower($3) !~ tolower(allow) && $3 != "" && $3 != "Unknown" {print $1 " :: " $3}' \
  | grep -ivE "MIT|Apache|BSD|ISC|MPL" | head -10)

if [[ -z "$OUT_OF_LIST" ]]; then
  _pass "21.3.1 every license is on the commercial-friendly allow-list"
else
  HITS=$(echo "$OUT_OF_LIST" | head -5 | tr '\n' '|')
  _fail "21.3.1 ${HITS} not on allow-list" "needs manual review"
fi

rm -f "$LIC_OUT"

# ── 21.4 go.sum integrity ──────────────────────────────────────────────────

phase_open "21.4 Module checksum integrity"

# `go mod verify` walks every module in go.sum and verifies the
# downloaded archive hash matches. A failure means a module on disk
# was tampered with or fetched from a poisoned mirror.
VOUT=$(go mod verify 2>&1)
if [[ "$VOUT" == "all modules verified" ]]; then
  _pass "21.4.1 go mod verify clean (every module hash matches go.sum)"
else
  _fail "21.4.1 go mod verify failed" "$VOUT"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
