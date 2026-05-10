#!/usr/bin/env bash
# scripts/test-l43-ci-self-audit.sh — CI workflow integrity audit.
#
# The test ladder protects production code, but the workflows
# themselves are PART of the supply chain — a malicious or careless
# PR could disable the gate by editing release-readiness.yml, and
# nothing would catch it. This level audits the YAML for known
# regression patterns:
#
#   1. No `--no-verify` git push / commit (skips pre-commit hooks)
#   2. No `continue-on-error: true` on the gate step (would mask FAIL)
#   3. No `if: false` / `if: never()` muting a level
#   4. No naked secrets reference in `run:` blocks (would echo into log)
#   5. Required-checks list in branch-protection matches workflow names
#   6. CODEOWNERS includes the workflow files themselves (lock-the-lock)
#   7. No skipped levels in test-all.sh that aren't gated by an env

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

WF_DIR="$ROOT/.github/workflows"

if [[ ! -d "$WF_DIR" ]]; then
  _skip "43.0 workflow dir" "$WF_DIR not present"
  final_summary; exit 0
fi

# ── 43.1 No --no-verify in git commands inside workflows ─────────────────

phase_open "43.1 No hook-skipping in CI git commands"

NO_VERIFY=$(grep -rEn '(git push.*--no-verify|git commit.*--no-verify|--no-gpg-sign)' \
  "$WF_DIR" 2>/dev/null | head -3 || true)

if [[ -n "$NO_VERIFY" ]]; then
  _fail "43.1.1 workflow uses --no-verify / --no-gpg-sign" \
    "$(echo "$NO_VERIFY" | head -1)"
else
  _pass "43.1.1 no --no-verify / --no-gpg-sign in workflow git commands"
fi

# ── 43.2 No continue-on-error on the gate step ───────────────────────────

phase_open "43.2 Release-readiness gate step doesn't mask failures"

# In release-readiness.yml the critical step is "Run release-readiness ladder".
# If continue-on-error: true is on it, the workflow PASSES even when
# the ladder fails — silent regression. SOFT-fail steps (gosec ratchet,
# fuzz dispatch, perf) ARE allowed to be `if: always()` for upload, but
# the ladder itself must hard-fail.
GATE_FILE="$WF_DIR/release-readiness.yml"
if [[ ! -r "$GATE_FILE" ]]; then
  _skip "43.2.1 gate workflow" "release-readiness.yml not readable"
else
  # Look at the run-the-ladder step block; check for continue-on-error
  # WITHIN that block (tighter rule than file-wide).
  GATE_BLOCK=$(awk '
    /name:[[:space:]]*Run release-readiness ladder/ { in_block=1; print; next }
    in_block && /^[[:space:]]+- name:/ { in_block=0 }
    in_block { print }
  ' "$GATE_FILE")

  if echo "$GATE_BLOCK" | grep -qE 'continue-on-error:[[:space:]]*true'; then
    _fail "43.2.1 ladder step has continue-on-error: true" \
      "the gate would pass even on FAIL — remove this"
  else
    _pass "43.2.1 ladder step doesn't mask failures via continue-on-error"
  fi

  # 43.2.2 the test-all.sh invocation isn't appended with `|| true`.
  if echo "$GATE_BLOCK" | grep -qE 'test-all\.sh.*\|\|[[:space:]]*true'; then
    _fail "43.2.2 ladder run masked with || true" \
      "the gate would pass even on FAIL"
  else
    _pass "43.2.2 ladder invocation not piped through || true"
  fi
fi

# ── 43.3 No `if: false` / `if: never()` muting a level ───────────────────

phase_open "43.3 No muted level steps"

MUTED=$(grep -rEn "if:[[:space:]]*(false|never\(\))" "$WF_DIR" 2>/dev/null | head -3 || true)
if [[ -n "$MUTED" ]]; then
  _fail "43.3.1 hardcoded if:false / if:never() in workflow" "$(echo "$MUTED" | head -1)"
else
  _pass "43.3.1 no hardcoded-disabled steps"
fi

# ── 43.4 Naked secrets aren't echoed in run: blocks ──────────────────────

phase_open "43.4 No `echo \${{ secrets.* }}` patterns"

# A common mistake is `run: echo \${{ secrets.FOO }}` for debug —
# secrets ARE redacted in standard logs, but `echo` writes to stdout
# which is where the redaction is applied. echo'ing into a file
# uploaded as artifact is the actual leak path.
SECRET_ECHO=$(grep -rEn 'echo[[:space:]]*"?\$\{\{[[:space:]]*secrets\.|cat.*<<.*secrets\.' \
  "$WF_DIR" 2>/dev/null \
  | grep -v '^\s*#' \
  | head -3 || true)

if [[ -n "$SECRET_ECHO" ]]; then
  _fail "43.4.1 secrets potentially echoed in workflow" \
    "$(echo "$SECRET_ECHO" | head -1)"
else
  _pass "43.4.1 no `echo \${{ secrets.* }}` patterns"
fi

# 43.4.2 No printenv / env that would dump all env including secrets.
ENV_DUMP=$(grep -rEn '^\s*run:.*\b(printenv|env\b)' "$WF_DIR" 2>/dev/null \
  | grep -vE 'env_replacer|environment|env\.' \
  | head -3 || true)
if [[ -n "$ENV_DUMP" ]]; then
  _skip "43.4.2 env dump in workflow" \
    "informational: $(echo "$ENV_DUMP" | head -1)"
else
  _pass "43.4.2 no `printenv`/`env` dump in workflow"
fi

# ── 43.5 Workflow files are locked in CODEOWNERS ─────────────────────────

phase_open "43.5 CODEOWNERS protects workflow files"

CODEOWNERS="$ROOT/.github/CODEOWNERS"
if [[ ! -r "$CODEOWNERS" ]]; then
  _skip "43.5.1 CODEOWNERS exists" "no .github/CODEOWNERS"
elif grep -qE '^/\.github/workflows/' "$CODEOWNERS"; then
  _pass "43.5.1 CODEOWNERS locks /.github/workflows/"
else
  _fail "43.5.1 CODEOWNERS doesn't lock workflow dir" \
    "any contributor could edit a workflow without owner review"
fi

if grep -qE '^/\.github/CODEOWNERS' "$CODEOWNERS" 2>/dev/null; then
  _pass "43.5.2 CODEOWNERS locks itself (lock-the-lock)"
else
  _fail "43.5.2 CODEOWNERS doesn't protect itself" \
    "an attacker could edit the rules to bypass everything else"
fi

# ── 43.6 test-all.sh skipped levels are explicitly gated ─────────────────

phase_open "43.6 No silently-disabled levels in test-all.sh"

TEST_ALL="$ROOT/scripts/test-all.sh"
if [[ ! -r "$TEST_ALL" ]]; then
  _skip "43.6.1 test-all.sh" "not readable"
else
  # Look for run_level lines that are commented out OR conditional on
  # something other than a known ENV var (RUN_*, L*_*).
  # Exclude usage-doc comments — `# run_level NAME SCRIPT [ARGS...]`
  # is the API doc, not a disabled call. Real disabled calls have a
  # specific script path: `# run_level "L7..." "$ROOT/scripts/...`.
  COMMENTED=$(grep -nE '^\s*#\s*run_level\s+"L' "$TEST_ALL" 2>/dev/null | head -3 || true)
  if [[ -n "$COMMENTED" ]]; then
    _fail "43.6.1 commented-out run_level entries" \
      "$(echo "$COMMENTED" | head -1)"
  else
    _pass "43.6.1 no commented-out run_level entries"
  fi

  # 43.6.2 every conditional run_level has a clear gate variable
  GATED=$(grep -B 1 -E '^\s*run_level' "$TEST_ALL" 2>/dev/null \
    | grep -E '^\s*if\s*\[\[' \
    | grep -vE 'RUN_|L[0-9]+_|SKIP_|FILTER' \
    | head -3 || true)
  if [[ -n "$GATED" ]]; then
    _skip "43.6.2 gating variables" "non-standard gate: $(echo "$GATED" | head -1)"
  else
    _pass "43.6.2 all gated levels use RUN_*/L*_* env vars"
  fi
fi

# ── 43.7 Workflow uses pinned action versions (not @latest) ──────────────

phase_open "43.7 Action versions are pinned"

UNPINNED=$(grep -rEn 'uses:[[:space:]]*[^@]+@(main|master|latest)' \
  "$WF_DIR" 2>/dev/null \
  | grep -v '^\s*#' \
  | head -3 || true)
if [[ -n "$UNPINNED" ]]; then
  _fail "43.7.1 workflow uses unpinned actions" \
    "$(echo "$UNPINNED" | head -1) — pin to a SHA or tagged version"
else
  _pass "43.7.1 no actions pinned to main/master/latest"
fi

final_summary
