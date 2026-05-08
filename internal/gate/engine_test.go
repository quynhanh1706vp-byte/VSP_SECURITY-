package gate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vsp/platform/internal/gate"
	"github.com/vsp/platform/internal/scanner"
)

func TestEvaluate_CleanScan(t *testing.T) {
	rule := gate.DefaultRule()
	s := scanner.Summary{}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionPass, r.Decision)
	assert.Equal(t, "A+", r.Posture) // Sprint 7.2: clean scan = A+ (score 100, ≥ 90 band)
	assert.Equal(t, 100, r.Score)
}

func TestEvaluate_CriticalBlocks(t *testing.T) {
	rule := gate.DefaultRule()
	s := scanner.Summary{Critical: 1}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionFail, r.Decision)
	assert.Equal(t, "F", r.Posture)
}

func TestEvaluate_SecretsBlock(t *testing.T) {
	rule := gate.DefaultRule()
	s := scanner.Summary{HasSecrets: true}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionFail, r.Decision)
	assert.Contains(t, r.Reason, "secrets")
}

func TestEvaluate_HighWarn(t *testing.T) {
	rule := gate.DefaultRule()
	rule.MaxHigh = -1 // unlimited — should only warn on HIGH
	rule.MinScore = 0 // disable score threshold to isolate MaxHigh behavior
	s := scanner.Summary{High: 5}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionWarn, r.Decision)
	// Sprint 7.3: under sqrt-based scoring, High:5 → score 82 → A band.
	// Pre-Sprint-7 the old hard-cap math floored this at 60 ("C") which
	// happened to match a user's intuition but produced indistinguishable
	// scores between 5 high and 50 high — see Score() docstring. The
	// gate decision (WARN — what this test actually exercises) is
	// unchanged; only the cosmetic letter shifts.
	assert.Equal(t, "A", r.Posture)
}

func TestEvaluate_MaxHighFail(t *testing.T) {
	rule := gate.DefaultRule()
	rule.MaxHigh = 2
	rule.FailOn = "FAIL"
	s := scanner.Summary{High: 5}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionFail, r.Decision)
}

func TestEvaluate_MaxHighWarnMode(t *testing.T) {
	rule := gate.DefaultRule()
	rule.MaxHigh = 2
	rule.FailOn = "WARN"
	rule.MinScore = 0 // disable score threshold to isolate FailOn=WARN behavior
	s := scanner.Summary{High: 5}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionWarn, r.Decision)
}

func TestEvaluate_ScoreThreshold(t *testing.T) {
	rule := gate.DefaultRule()
	rule.BlockCritical = false // disable block để test score threshold
	rule.MinScore = 90
	// Critical:1 = -15, High:1 = -8 → score 77 < 90
	s := scanner.Summary{Critical: 1, High: 1}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionFail, r.Decision)
	assert.Equal(t, 77, r.Score)
}

// TestPosture pins the SINGLE-SOURCE-OF-TRUTH letter grade contract.
// Sprint 7.2 unified the previously-divergent count-based Go grader
// and the score-based JS dashboard grader. The new contract is:
//
//   1. Critical > 0  → F (hard fail, regardless of score)
//   2. HasSecrets    → F (hard fail, regardless of score)
//   3. Otherwise, A+/A/B/C/D bands derived from gate.Score(s).
//
// This test is also the canonical example for any new UI that wants
// to render a grade — call gate.Posture() and never compute locally.
func TestPosture(t *testing.T) {
	cases := []struct {
		name    string
		s       scanner.Summary
		posture string
	}{
		// Score-band cases — clean runs with progressively worse findings.
		// Sprint 7.3: scores below come from sqrt-based penalties.
		// sqrt(n) * weight (rounded). Verified manually:
		//   High:1   = 100 - 8*1   = 92    → A+
		//   High:2   = 100 - 8*~1.4 ≈ 89  → A
		//   High:5   = 100 - 8*~2.2 ≈ 82  → A
		//   High:25  = 100 - 8*5    = 60   → C  (lossier than 5×8=40 cap)
		{"empty → A+ (score 100)", scanner.Summary{}, "A+"},
		{"single medium → A+ (score 98)", scanner.Summary{Medium: 1}, "A+"},
		{"two high → A (score ~89)", scanner.Summary{High: 2}, "A"},
		{"five high → A (score ~82)", scanner.Summary{High: 5}, "A"},
		{"twenty-five high → C (score 60)", scanner.Summary{High: 25}, "C"},
		{"hundred high → F floor", scanner.Summary{High: 100}, "F"},
		// Hard-fail cases — critical or secrets always produce F.
		{"any critical → F regardless of score", scanner.Summary{Critical: 1}, "F"},
		{"live secrets → F regardless of score", scanner.Summary{HasSecrets: true}, "F"},
		{"critical + everything → F", scanner.Summary{Critical: 5, High: 50, HasSecrets: true}, "F"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.posture, gate.Posture(c.s),
				"summary=%+v score=%d", c.s, gate.Score(c.s))
		})
	}
}

// TestScore — sqrt-based penalties (Sprint 7.3). The numbers below are
// the output of the production scoring function and are pinned so any
// future weight retune is an explicit, reviewed change rather than a
// silent dashboard regression.
func TestScore(t *testing.T) {
	assert.Equal(t, 100, gate.Score(scanner.Summary{}))
	assert.Equal(t, 92, gate.Score(scanner.Summary{High: 1}))   // 100 - 8*sqrt(1)
	assert.Equal(t, 85, gate.Score(scanner.Summary{Critical: 1})) // 100 - 15*sqrt(1)
	// Critical: 10 — under the OLD capped math this was 70 ("2 capped × 15");
	// the new math discriminates (10 critical IS worse than 2 critical):
	// 15*sqrt(10) ≈ 47, score ≈ 53.
	assert.Equal(t, 53, gate.Score(scanner.Summary{Critical: 10}))
	assert.Equal(t, 75, gate.Score(scanner.Summary{HasSecrets: true})) // 100 - 25
	assert.Equal(t, 60, gate.Score(scanner.Summary{HasSecrets: true, Critical: 1})) // 100-25-15
	// Large-volume case: 100 high reaches the floor cleanly.
	assert.Equal(t, 20, gate.Score(scanner.Summary{High: 100})) // 100 - 8*sqrt(100) = 100-80
}
