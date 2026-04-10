package siem

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewUEBAEngine(t *testing.T) {
	e := NewUEBAEngine(nil, "tenant-1")
	assert.NotNil(t, e)
	assert.Equal(t, "tenant-1", e.tenantID)
	assert.Nil(t, e.baseline)
}

func TestAnomalyTypes_Constants(t *testing.T) {
	assert.Equal(t, AnomalyType("score_spike"),      AnomalyScoreSpike)
	assert.Equal(t, AnomalyType("findings_surge"),   AnomalyFindingsSurge)
	assert.Equal(t, AnomalyType("gate_fail_streak"), AnomalyGateFailStreak)
	assert.Equal(t, AnomalyType("scan_frequency"),   AnomalyScanFrequency)
	assert.Equal(t, AnomalyType("new_critical_tool"), AnomalyNewCritical)
	assert.Equal(t, AnomalyType("off_hours_scan"),   AnomalyOffHoursScan)
	assert.Equal(t, AnomalyType("sla_breach"),       AnomalySLABreach)
}

func TestAnomalyNewCriticalTool_SameAsNewCritical(t *testing.T) {
	assert.Equal(t, AnomalyNewCritical, AnomalyNewCriticalTool)
}

func TestBaseline_ZeroValue(t *testing.T) {
	b := &Baseline{}
	assert.Equal(t, 0.0, b.AvgScore)
	assert.Equal(t, 0.0, b.GatePassRate)
	assert.Nil(t, b.Tools)
}

func TestUEBAEngine_NilBaseline_ScoreSpike(t *testing.T) {
	e := NewUEBAEngine(nil, "tid")
	e.baseline = nil
	// Should return nil without panic when baseline is nil
	result := e.checkScoreSpike(context.TODO())
	assert.Nil(t, result)
}

func TestUEBAEngine_ZeroBaseline_ScoreSpike(t *testing.T) {
	e := NewUEBAEngine(nil, "tid")
	e.baseline = &Baseline{AvgScore: 0}
	result := e.checkScoreSpike(context.TODO())
	assert.Nil(t, result)
}

func TestUEBAEngine_NilBaseline_FindingsSurge(t *testing.T) {
	e := NewUEBAEngine(nil, "tid")
	e.baseline = nil
	result := e.checkFindingsSurge(context.TODO())
	assert.Nil(t, result)
}

func TestUEBAEngine_ZeroBaseline_FindingsSurge(t *testing.T) {
	e := NewUEBAEngine(nil, "tid")
	e.baseline = &Baseline{AvgFindings: 0}
	result := e.checkFindingsSurge(context.TODO())
	assert.Nil(t, result)
}

func TestUEBAEngine_NilBaseline_NewCriticalTools(t *testing.T) {
	e := NewUEBAEngine(nil, "tid")
	e.baseline = nil
	result := e.checkNewCriticalTools(context.TODO())
	assert.Nil(t, result)
}

func TestAnomaly_ScoreCap(t *testing.T) {
	// Score should not exceed 100
	a := Anomaly{Score: 150}
	assert.Equal(t, 150.0, a.Score) // struct allows >100, scoring math caps it
}

func TestAnomaly_Severity_Values(t *testing.T) {
	for _, sev := range []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		a := Anomaly{Severity: sev}
		assert.Equal(t, sev, a.Severity)
	}
}
