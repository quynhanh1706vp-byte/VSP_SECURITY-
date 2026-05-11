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
TARGET_AUDIT="$ROOT/internal/audit/chain.go"
TARGET_AUTH="$ROOT/internal/auth/lockout.go"
TARGET_CRYPTO="$ROOT/internal/crypto/aesgcm.go"
for f in "$TARGET" "$TARGET_AUDIT" "$TARGET_AUTH" "$TARGET_CRYPTO"; do
  if [[ ! -f "$f" ]]; then
    printf "%s✗%s target %s missing\n" "$C_RED" "$C_RESET" "$f" >&2
    exit 2
  fi
done

# Save originals; restore on EXIT.
ORIG=$(mktemp)
ORIG_AUDIT=$(mktemp)
ORIG_AUTH=$(mktemp)
ORIG_CRYPTO=$(mktemp)
cp "$TARGET"        "$ORIG"
cp "$TARGET_AUDIT"  "$ORIG_AUDIT"
cp "$TARGET_AUTH"   "$ORIG_AUTH"
cp "$TARGET_CRYPTO" "$ORIG_CRYPTO"
restore() {
  cp "$ORIG"        "$TARGET"
  cp "$ORIG_AUDIT"  "$TARGET_AUDIT"
  cp "$ORIG_AUTH"   "$TARGET_AUTH"
  cp "$ORIG_CRYPTO" "$TARGET_CRYPTO"
  rm -f "$ORIG" "$ORIG_AUDIT" "$ORIG_AUTH" "$ORIG_CRYPTO"
}
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
#   mutate          NAME DESCRIPTION SED_EXPR  → gate package
#   mutate_audit    NAME DESCRIPTION SED_EXPR  → internal/audit
#   mutate_auth     NAME DESCRIPTION SED_EXPR  → internal/auth/lockout
#
# Each variant operates on its own target file + tests against its own
# package only. Original is restored before each mutation.
KILLS=0
SURVIVORS=()

_run_mutation() {
  local name="$1" desc="$2" sed_expr="$3" target="$4" pkg="$5" pristine="$6"
  cp "$pristine" "$target"
  if ! sed -i "$sed_expr" "$target"; then
    _fail "13.2.$name" "sed expression failed: $sed_expr"
    return
  fi
  if diff -q "$pristine" "$target" > /dev/null 2>&1; then
    _skip "13.2.$name" "mutation no-op (pattern didn't match): $desc"
    return
  fi
  if ! go build "$pkg/..." > /tmp/l11_build.log 2>&1; then
    _skip "13.2.$name" "mutation breaks compile: $desc"
    rm -f /tmp/l11_build.log
    return
  fi
  rm -f /tmp/l11_build.log
  if go test -count=1 -timeout 60s "$pkg/..." > /tmp/l11_run.log 2>&1; then
    SURVIVORS+=("$name: $desc")
    _fail "13.2.$name" "MUTATION SURVIVED — no test caught: $desc"
  else
    KILLS=$((KILLS+1))
    _pass "13.2.$name killed [$desc]"
  fi
  rm -f /tmp/l11_run.log
}

mutate()       { _run_mutation "$1" "$2" "$3" "$TARGET"       "./internal/gate"  "$ORIG";       }
mutate_audit() { _run_mutation "$1" "$2" "$3" "$TARGET_AUDIT" "./internal/audit" "$ORIG_AUDIT"; }
mutate_auth()  { _run_mutation "$1" "$2" "$3" "$TARGET_AUTH"  "./internal/auth"  "$ORIG_AUTH";  }
mutate_crypto(){ _run_mutation "$1" "$2" "$3" "$TARGET_CRYPTO" "./internal/crypto" "$ORIG_CRYPTO"; }

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

# ── 13.2.audit_* — internal/audit chain.go mutations ──────────────────────
#
# Hash chain math is the integrity backbone: any mutation here would let
# an attacker forge audit entries while keeping verify ok=true. Every
# mutation here MUST be killed by audit's tests.

# A1: drop Seq from the hash input — hash becomes order-independent,
# attacker can swap rows without breaking chain.
mutate_audit "A1_seq_dropped" \
  "Hash() drops Seq from inputs" \
  's/"%d|%s|%s|%s|%s",[[:space:]]*$/"%s|%s|%s|%s",/; s/e\.Seq, e\.TenantID, e\.Action, e\.Resource, e\.PrevHash/e.TenantID, e.Action, e.Resource, e.PrevHash/'

# A2: drop PrevHash — chain becomes a flat set, no ordering.
mutate_audit "A2_prevhash_dropped" \
  "Hash() drops PrevHash from inputs" \
  's/, e\.PrevHash)/)/; s/"%d|%s|%s|%s|%s"/"%d|%s|%s|%s"/'

# A3: TenantID dropped — cross-tenant rows would chain together.
mutate_audit "A3_tenant_dropped" \
  "Hash() drops TenantID — cross-tenant chain merge" \
  's/e\.Seq, e\.TenantID, e\.Action/e.Seq, e.Action/; s/"%d|%s|%s|%s|%s"/"%d|%s|%s|%s"/'

# ── 13.2.auth_* — internal/auth/lockout.go mutations ──────────────────────

# AU1: per-IP threshold relaxed (20 → 200) — credential stuffing
# defense neutered.
mutate_auth "AU1_threshold_relaxed" \
  "ipFailLimit 20 → 200" \
  's/ipFailLimit[[:space:]]*=[[:space:]]*20$/ipFailLimit   = 200/'

# AU2: lockout duration shrunk (15min → 1s) — attacker waits 1s
# between bursts.
mutate_auth "AU2_lockout_shortened" \
  "ipLockoutTime 15 minutes → 1 second" \
  's/ipLockoutTime = 15 \* time\.Minute/ipLockoutTime = 1 * time.Second/'

# AU3: BackoffSleep returns immediately — no exponential delay.
mutate_auth "AU3_backoff_neutered" \
  "BackoffSleep early return — no delay applied" \
  's/^func BackoffSleep(failedCount int) {/func BackoffSleep(failedCount int) { return; if false {/'

# ── 13.2.crypto_* — internal/crypto/aesgcm.go mutations ─────────────────────
# Drop sentinel comparisons so caller's switch on err type stops working.
# Tests in errors_test.go (TestDecrypt_WrongKey_L60 / _TamperedCiphertext_L60)
# assert errors.Is(err, ErrTamper) — these mutations should kill cleanly.

# C1: Replace ErrTamper with a different error — `errors.Is` callers
# now fall through to default branch.
mutate_crypto "C1_errtamper_renamed" \
  "ErrTamper sentinel replaced with generic error — errors.Is fails" \
  's/ErrTamper = errors\.New("crypto: ciphertext tampered or wrong key")/ErrTamper = errors.New("crypto: other")/'

# C2: Skip empty-passphrase guard — empty key becomes SHA256("").
mutate_crypto "C2_empty_passphrase_accepted" \
  "NewFromPassphrase no longer rejects empty input" \
  's/if passphrase == "" {/if false {/'

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
