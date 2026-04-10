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
	assert.Equal(t, "A", r.Posture)
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
	assert.Equal(t, "C", r.Posture) // High:5 > 2 → C
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

func TestPosture(t *testing.T) {
	cases := []struct {
		s       scanner.Summary
		posture string
	}{
		{scanner.Summary{}, "A"},
		{scanner.Summary{Medium: 1}, "B"},
		{scanner.Summary{High: 1}, "B"},
		{scanner.Summary{High: 3}, "C"},
		{scanner.Summary{Medium: 6}, "C"},
		{scanner.Summary{High: 11}, "D"},
		{scanner.Summary{Critical: 1}, "F"},
	}
	for _, c := range cases {
		assert.Equal(t, c.posture, gate.Posture(c.s))
	}
}

func TestScore(t *testing.T) {
	assert.Equal(t, 100, gate.Score(scanner.Summary{}))
	assert.Equal(t, 92, gate.Score(scanner.Summary{High: 1}))                       // 100-8
	assert.Equal(t, 85, gate.Score(scanner.Summary{Critical: 1}))                   // 100-15
	assert.Equal(t, 70, gate.Score(scanner.Summary{Critical: 10}))                  // 100-30 (capped)
	assert.Equal(t, 75, gate.Score(scanner.Summary{HasSecrets: true}))              // 100-25
	assert.Equal(t, 60, gate.Score(scanner.Summary{HasSecrets: true, Critical: 1})) // 100-25-15
}
