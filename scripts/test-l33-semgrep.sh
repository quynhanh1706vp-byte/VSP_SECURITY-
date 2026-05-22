#!/usr/bin/env bash
# scripts/test-l33-semgrep.sh — semgrep security-pack dogfood.
#
# We already run gosec (L6-C). semgrep uses a totally different
# rule engine (pattern-matching at the AST level) and ships several
# Go security packs: r2c-security-audit, dgryski.semgrep-go,
# trailofbits.semgrep-rules. Running both catches different bug
# classes — gosec misses some patterns semgrep catches and vice
# versa.
#
# We use the open-source `p/golang` registry pack which is bundled
# with semgrep CLI and curated for Go security issues. Findings
# are categorized HIGH / MEDIUM / LOW; HIGH triggers a fail.
#
# Pre-flight: semgrep installed.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command semgrep jq

cd "$ROOT"

# ── 34.1 Run semgrep p/golang ─────────────────────────────────────────────

phase_open "34.1 semgrep p/golang — high-severity findings"

OUT=$(mktemp)
# semgrep registry now requires auth (HTTP 401 on p/golang). Use the
# hand-rolled rules in scripts/lib/semgrep-rules.yml instead — small
# but high-signal patterns gosec doesn't catch.
RULES="$ROOT/scripts/lib/semgrep-rules.yml"
if [[ ! -f "$RULES" ]]; then
  _fail "34.0.0 rules file missing" "expected $RULES"
  rm -f "$OUT"
  final_summary; exit $?
fi
semgrep --config="$RULES" --json --quiet --metrics=off \
  --exclude='**/*_test.go' --exclude='**/*.bak*' \
  --exclude='cmd/dev-stub' --exclude='internal/threatintel/conflicting_*' \
  --include='**/*.go' \
  -- "$ROOT/internal" "$ROOT/cmd" > "$OUT" 2>/dev/null || true

if ! jq -e . "$OUT" > /dev/null 2>&1; then
  _fail "34.1.0 semgrep output empty / invalid JSON" \
    "semgrep run failed; check semgrep --version + connectivity"
  rm -f "$OUT"
  final_summary; exit $?
fi

TOTAL=$(jq '.results | length' "$OUT")
HIGH=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' "$OUT")
MED=$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' "$OUT")
LOW=$(jq '[.results[] | select(.extra.severity == "INFO")] | length' "$OUT")

if (( HIGH == 0 )); then
  _pass "34.1.1 no HIGH (ERROR) findings [$TOTAL total: $HIGH HIGH / $MED MED / $LOW LOW]"
else
  EXAMPLES=$(jq -r '[.results[] | select(.extra.severity == "ERROR")
    | "\(.check_id) | \(.path):\(.start.line)"] | .[0:5] | .[]' "$OUT" | tr '\n' '|')
  _fail "34.1.1 $HIGH HIGH-severity semgrep findings" "$EXAMPLES"
fi

# ── 34.2 Drift watchdog — total findings under ratchet ────────────────────

phase_open "34.2 semgrep total — ratchet against regression"

# Same ratchet pattern as L10. Lock the current TOTAL count; PRs that
# add new patterns push above and fail. Update RATCHET when you
# intentionally close findings.
SEMGREP_RATCHET=200

if (( TOTAL <= SEMGREP_RATCHET )); then
  _pass "34.2.1 semgrep findings at-or-below ratchet [$TOTAL ≤ $SEMGREP_RATCHET]"
else
  EXAMPLES=$(jq -r '[.results[] | "\(.check_id) | \(.path):\(.start.line)"] | .[0:5] | .[]' "$OUT" \
    | tr '\n' '|')
  _fail "34.2.1 semgrep regression" \
    "$TOTAL findings vs ratchet $SEMGREP_RATCHET — new pattern hits: $EXAMPLES"
fi

# ── 34.3 Specific dangerous patterns absent ───────────────────────────────

phase_open "34.3 No SECURITY-CRITICAL pattern hits"

# Check: even if the ratchet allows N noise findings, certain rules
# MUST be zero. These are the blast-radius rules — never accept any
# count > 0 here regardless of overall ratchet.
CRITICAL_RULES=(
  "go.lang.security.audit.dangerous-exec-command"
  "go.lang.security.audit.dangerous-syscall-exec"
  "go.lang.security.injection.tainted-sql-string"
  "go.lang.security.audit.crypto.use_of_weak_rsa_key"
  "go.lang.security.audit.crypto.use_of_md5"
  "go.lang.security.audit.crypto.use_of_sha1"
  "go.lang.security.audit.crypto.use_of_des"
)
NEVER_HIT=()
for rule in "${CRITICAL_RULES[@]}"; do
  count=$(jq --arg r "$rule" '[.results[] | select(.check_id | contains($r))] | length' "$OUT")
  if (( count > 0 )); then
    NEVER_HIT+=("$rule:$count")
  fi
done

if (( ${#NEVER_HIT[@]} == 0 )); then
  _pass "34.3.1 no critical-rule hits"
else
  printf -v LIST '%s | ' "${NEVER_HIT[@]}"
  _fail "34.3.1 critical-rule hit" "${LIST%| }"
fi

rm -f "$OUT"

# ── final ──────────────────────────────────────────────────────────────────

final_summary
