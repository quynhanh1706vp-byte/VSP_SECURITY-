// Package gate — property-based tests (L4-A).
//
// Where engine_test.go covers specific input/output pairs, this file
// asserts INVARIANTS that must hold for all valid Summary values.
// Each property runs `quick.Check` with 10k randomized inputs.
//
// Catches the bug class that pre-Sprint-7.3 hard-cap math hid for
// months: math regressions where unit tests still pass with stale
// fixtures while real-world inputs violate a structural property
// (e.g. "more findings → strictly worse score").
package gate

import (
	"math/rand"
	"testing"
	"testing/quick"

	"github.com/vsp/platform/internal/scanner"
)

// boundedSummary keeps random Summary in realistic ranges so quick
// doesn't generate negative counts (which Score is not specified for)
// or absurdly large ones that overflow penalty math.
func boundedSummary(r *rand.Rand) scanner.Summary {
	return scanner.Summary{
		Critical:      r.Intn(500),
		High:          r.Intn(2000),
		Medium:        r.Intn(5000),
		Low:           r.Intn(10000),
		Info:          r.Intn(10000),
		HasSecrets:    r.Intn(2) == 0,
		DASTConfirmed: r.Intn(50),
		DASTRan:       r.Intn(2) == 0,
		WeightedHigh:  r.Intn(20000),
		WeightedCrit:  r.Intn(5000),
	}
}

// Property 1: Score is bounded to [0, 100] for any input.
func TestProp_ScoreInRange(t *testing.T) {
	prop := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		s := boundedSummary(r)
		got := Score(s)
		return got >= 0 && got <= 100
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 10000}); err != nil {
		t.Errorf("Score range invariant violated: %v", err)
	}
}

// Property 2: Posture only returns canonical letters.
// Catches a regression where someone adds a "B+" or "F-" tier and
// breaks the JSON contract that dashboard JS depends on.
func TestProp_PostureValidLetter(t *testing.T) {
	valid := map[string]bool{"A+": true, "A": true, "B": true, "C": true, "D": true, "F": true}
	prop := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		s := boundedSummary(r)
		return valid[Posture(s)]
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 10000}); err != nil {
		t.Errorf("Posture letter invariant violated: %v", err)
	}
}

// Property 3: Critical>0 ALWAYS forces F. The pre-Sprint-7 bug was a
// dashboard JS path that returned "D · 1 critical" — auditor-trust
// killer. This property pins the contract.
func TestProp_CriticalForcesF(t *testing.T) {
	prop := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		s := boundedSummary(r)
		s.Critical = r.Intn(100) + 1 // guarantee ≥ 1
		return Posture(s) == "F"
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 5000}); err != nil {
		t.Errorf("Critical>0 must force F, violated: %v", err)
	}
}

// Property 4: HasSecrets=true ALWAYS forces F regardless of all other counts.
func TestProp_SecretsForceF(t *testing.T) {
	prop := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		s := boundedSummary(r)
		s.HasSecrets = true
		s.Critical = 0 // isolate: secrets-only path must still F
		return Posture(s) == "F"
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 5000}); err != nil {
		t.Errorf("HasSecrets must force F, violated: %v", err)
	}
}

// Property 5: Posture is deterministic — same input → same letter.
// Catches accidental introduction of map iteration / time / random in
// the grading path.
func TestProp_PostureDeterministic(t *testing.T) {
	prop := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		s := boundedSummary(r)
		first := Posture(s)
		for i := 0; i < 5; i++ {
			if Posture(s) != first {
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Errorf("Posture must be deterministic, violated: %v", err)
	}
}

// Property 6: Adding one HIGH finding cannot INCREASE the score.
// (Equality OK because hard-fail or floor=0 may already dominate.)
// This is the property the pre-Sprint-7.3 cap math violated for large
// counts — it was the original "2032 findings reads same as 50" bug.
func TestProp_MonotonicHigh(t *testing.T) {
	prop := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		s := boundedSummary(r)
		s.Critical = 0 // avoid hard-fail path collapsing the test
		s.HasSecrets = false
		s.WeightedCrit = 0
		s.WeightedHigh = 0
		before := Score(s)
		s.High++
		after := Score(s)
		return after <= before
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 5000}); err != nil {
		t.Errorf("Score must not increase when adding HIGH, violated: %v", err)
	}
}

// Property 7: Adding one MEDIUM finding cannot increase the score.
func TestProp_MonotonicMedium(t *testing.T) {
	prop := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		s := boundedSummary(r)
		s.Critical = 0
		s.HasSecrets = false
		s.WeightedCrit = 0
		s.WeightedHigh = 0
		before := Score(s)
		s.Medium++
		after := Score(s)
		return after <= before
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 5000}); err != nil {
		t.Errorf("Score must not increase when adding MEDIUM, violated: %v", err)
	}
}

// Property 8: Adding one LOW finding cannot increase the score.
func TestProp_MonotonicLow(t *testing.T) {
	prop := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		s := boundedSummary(r)
		s.Critical = 0
		s.HasSecrets = false
		s.WeightedCrit = 0
		s.WeightedHigh = 0
		before := Score(s)
		s.Low++
		after := Score(s)
		return after <= before
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 5000}); err != nil {
		t.Errorf("Score must not increase when adding LOW, violated: %v", err)
	}
}

// Property 9: Empty Summary {} must produce A+ (perfect run).
// This is a fixture-independent contract probe.
func TestProp_EmptyIsAPlus(t *testing.T) {
	if got := Posture(scanner.Summary{}); got != "A+" {
		t.Errorf("empty Summary should be A+, got %s", got)
	}
}

// Property 10: Hard-fail dominates DAST bonus.
// Pre-Sprint-7.3 a clean DAST run could push score above the hard-fail
// threshold; this property locks the precedence.
func TestProp_HardFailDominatesDASTBonus(t *testing.T) {
	prop := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		s := boundedSummary(r)
		s.DASTRan = true
		s.DASTConfirmed = 0
		s.Critical = 1
		return Posture(s) == "F"
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 2000}); err != nil {
		t.Errorf("DAST bonus must not override hard-fail, violated: %v", err)
	}
}
