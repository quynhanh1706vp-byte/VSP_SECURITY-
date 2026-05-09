#!/usr/bin/env bash
# scripts/test-l11-mutation.sh — hand-rolled mutation testing on critical packages.
#
# Mutation testing validates that our test suite would CATCH a regression
# if someone "innocently" weakened the source. We apply small, semantically-
# meaningful mutations to internal/gate/engine.go (the math the dashboard
# depends on) and run `go test ./internal/gate/...`. Every mutation MUST
# break at least one test — if a mutation passes, the corresponding test
# is vacuous (doesn't actually pin the property it claims to).
#
# We can't use the off-the-shelf go-mutesting; it panics on Go 1.25 module
# mode (last release predates the new toolchain semantics). A hand-rolled
# bash + sed approach is more robust and gives us control over which
# mutations we care about.
#
# Mutations applied (all reversible — original file restored on exit):
#   M1: > → >=     (boundary off-by-one in score)
#   M2: <  → <=    (band threshold inversion in LetterGrade)
#   M3: + → -      (sign error in Score arithmetic)
#   M4: && → ||    (predicate weakening in hard-fail check)
#   M5: return -1  (sentinel-pollution: tests that don't probe range fail)
#   M6: comment out "if score < 0 { return 0 }" floor (boundary)
#
# Pre-flight: go toolchain installed.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command go sed diff

TARGET="$ROOT/internal/gate/engine.go"
if [[ ! -f "$TARGET" ]]; then
  printf "%s✗%s target file %s missing\n" "$C_RED" "$C_RESET" "$TARGET" >&2
  exit 2
fi

# Save original; restore on EXIT no matter how we leave.
ORIG=$(mktemp)
cp "$TARGET" "$ORIG"
restore() { cp "$ORIG" "$TARGET"; rm -f "$ORIG"; }
trap restore EXIT

# Verify baseline tests pass before mutating. If they don't, every
# mutation will look like a "kill" for the wrong reason.
phase_open "13.1 Mutation baseline — confirm tests pass on pristine source"

if go test -count=1 -timeout 60s ./internal/gate/... > /tmp/l11_base.log 2>&1; then
  _pass "13.1.1 baseline tests pass on pristine source"
else
  TAIL=$(tail -8 /tmp/l11_base.log | tr '\n' '|')
  _fail "13.1.1 baseline tests fail" "tests fail before any mutation: $TAIL"
  rm -f /tmp/l11_base.log
  exit 1
fi
rm -f /tmp/l11_base.log

# Helper: apply a mutation, run tests, report kill/survive, restore source.
#
#   apply_mutation NAME DESCRIPTION SED_EXPR [LINE_FILTER]
#
# The mutation kills if `go test` exits non-zero (a test caught the change).
# It survives if tests still pass — meaning the regression would ship.
KILLS=0
SURVIVORS=()
mutate() {
  local name="$1" desc="$2" sed_expr="$3"
  cp "$ORIG" "$TARGET"   # always start from pristine
  if ! sed -i "$sed_expr" "$TARGET"; then
    _fail "13.2.$name" "sed expression failed: $sed_expr"
    return
  fi
  # Did the mutation actually change anything?
  if diff -q "$ORIG" "$TARGET" > /dev/null 2>&1; then
    _skip "13.2.$name" "mutation no-op (pattern didn't match): $desc"
    return
  fi
  # Compile check first — uncompilable mutations are not interesting.
  if ! go build ./internal/gate/... > /tmp/l11_build.log 2>&1; then
    _skip "13.2.$name" "mutation breaks compile: $desc"
    rm -f /tmp/l11_build.log
    return
  fi
  rm -f /tmp/l11_build.log
  if go test -count=1 -timeout 60s ./internal/gate/... > /tmp/l11_run.log 2>&1; then
    SURVIVORS+=("$name: $desc")
    _fail "13.2.$name" "MUTATION SURVIVED — no test caught: $desc"
  else
    KILLS=$((KILLS+1))
    _pass "13.2.$name killed [$desc]"
  fi
  rm -f /tmp/l11_run.log
}

# ── 13.2 mutations ─────────────────────────────────────────────────────────

phase_open "13.2 Apply mutations and assert tests catch each one"

# M1: bands threshold tighten — `>= 90` becomes `> 90`. Score=90 → A
# instead of A+. TestProp_PostureValidLetter wouldn't catch (still
# valid letter); TestPosturePinnedExamples (engine_test.go) should.
mutate "M1_band_strict" \
       "score >= 90 → score > 90 (LetterGrade band)" \
       's/case score >= 90:/case score > 90:/'

# M2: hard-fail relaxed — `Critical > 0` → `Critical > 1`. Single
# critical no longer forces F. Property TestProp_CriticalForcesF
# MUST catch this.
mutate "M2_critical_relaxed" \
       "Critical > 0 → Critical > 1 (hard-fail check)" \
       's/s\.Critical > 0 || s\.HasSecrets/s.Critical > 1 || s.HasSecrets/'

# M3: sign flip on a single penalty — high penalty subtracted →
# added. Adding a high finding would IMPROVE the score. Property
# TestProp_MonotonicHigh MUST catch.
mutate "M3_high_sign" \
       "highPenalty subtracted → added (sign flip)" \
       's/100 - critPenalty - highPenalty - medPenalty/100 - critPenalty + highPenalty - medPenalty/'

# M4: floor removed — `if score < 0 { return 0 }` neutered. Score
# can go negative for very large finding counts. Property
# TestProp_ScoreInRange MUST catch.
mutate "M4_floor_removed" \
       "score < 0 floor removed" \
       's/if score < 0 {/if score < -10000 {/'

# M5: ceiling raised — `if score > 100 { return 100 }` neutered.
# DAST bonus could push above 100. Property TestProp_ScoreInRange
# MUST catch.
mutate "M5_ceiling_raised" \
       "score > 100 ceiling neutered" \
       's/if score > 100 {/if score > 200 {/'

# M6: hard-fail OR weakened to AND. Critical AND Secrets needed
# instead of EITHER. Property TestProp_SecretsForceF MUST catch
# (HasSecrets=true alone but Critical=0 stops forcing F).
mutate "M6_hardfail_and" \
       "Critical||HasSecrets → Critical&&HasSecrets" \
       's/s\.Critical > 0 || s\.HasSecrets/s.Critical > 0 \&\& s.HasSecrets/'

# ── 13.3 summary ───────────────────────────────────────────────────────────

phase_open "13.3 Mutation score"

ATTEMPTED=$((KILLS + ${#SURVIVORS[@]}))
if (( ATTEMPTED == 0 )); then
  _fail "13.3.1 mutation score" "no mutations actually applied (all skipped)"
elif (( ${#SURVIVORS[@]} == 0 )); then
  _pass "13.3.1 mutation score: $KILLS/$ATTEMPTED killed (100%)"
else
  _fail "13.3.1 surviving mutations" \
    "${#SURVIVORS[@]}/$ATTEMPTED survived: ${SURVIVORS[*]}"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
