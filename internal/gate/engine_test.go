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
	rule.MaxHigh = -1 // unlimited — should only warn
	s := scanner.Summary{High: 5}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionWarn, r.Decision)
	assert.Equal(t, "B", r.Posture)
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
	s := scanner.Summary{High: 5}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionWarn, r.Decision)
}

func TestEvaluate_ScoreThreshold(t *testing.T) {
	rule := gate.DefaultRule()
	rule.MinScore = 80
	// 10 medium findings = -30 → score 70
	s := scanner.Summary{Medium: 10}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionFail, r.Decision)
	assert.Equal(t, 70, r.Score)
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
	assert.Equal(t, 90, gate.Score(scanner.Summary{High: 1}))  // 100-10
	assert.Equal(t, 75, gate.Score(scanner.Summary{Critical: 1})) // 100-25
	assert.Equal(t, 0, gate.Score(scanner.Summary{Critical: 10})) // floored at 0
}
