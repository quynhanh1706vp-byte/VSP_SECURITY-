package governance

import (
	"testing"
	"time"

	"github.com/vsp/platform/internal/store"
)

func makeFindings(severities ...string) []store.Finding {
	findings := make([]store.Finding, len(severities))
	for i, sev := range severities {
		findings[i] = store.Finding{
			ID:       "f" + string(rune('0'+i)),
			Severity: sev,
			Tool:     "trivy",
			RuleID:   "CVE-2024-0001",
			Message:  "test finding",
			CWE:      "CWE-79",
		}
	}
	return findings
}

func TestBuildRiskRegister_Empty(t *testing.T) {
	items := BuildRiskRegister("tenant-1", []store.Finding{})
	if items == nil {
		t.Error("expected non-nil slice")
	}
}

func TestBuildRiskRegister_WithFindings(t *testing.T) {
	findings := makeFindings("CRITICAL", "HIGH", "MEDIUM", "LOW")
	items := BuildRiskRegister("tenant-1", findings)
	if len(items) == 0 {
		t.Error("expected risk items from findings")
	}
	// Critical findings should have high risk level
	for _, item := range items {
		if item.Level == "" {
			t.Error("risk item should have a level")
		}
	}
}

func TestBuildTraceability(t *testing.T) {
	findings := makeFindings("HIGH", "MEDIUM")
	rows := BuildTraceability(findings)
	if rows == nil {
		t.Error("expected non-nil result")
	}
}

func TestBuildFrameworkScorecard_Empty(t *testing.T) {
	scores := BuildFrameworkScorecard([]store.Finding{})
	if len(scores) == 0 {
		t.Error("expected framework scores even with no findings")
	}
	// All scores should be 0-100
	for _, s := range scores {
		if s.Score < 0 || s.Score > 100 {
			t.Errorf("score %q out of range: %d", s.Framework, s.Score)
		}
	}
}

func TestBuildFrameworkScorecard_WithFindings(t *testing.T) {
	findings := makeFindings("CRITICAL", "CRITICAL", "HIGH")
	scores := BuildFrameworkScorecard(findings)
	for _, s := range scores {
		if s.Score < 0 || s.Score > 100 {
			t.Errorf("score %q out of range: %d", s.Framework, s.Score)
		}
	}
}

func TestBuildZeroTrust(t *testing.T) {
	findings := makeFindings("HIGH", "MEDIUM")
	pillars := BuildZeroTrust(findings)
	if len(pillars) == 0 {
		t.Error("expected zero trust pillars")
	}
}

func TestBuildSecurityRoadmap(t *testing.T) {
	findings := makeFindings("CRITICAL", "HIGH")
	items := BuildSecurityRoadmap(findings, "C")
	if len(items) == 0 {
		t.Error("expected roadmap items")
	}
}

func TestBuildRACI(t *testing.T) {
	raci := BuildRACI()
	if len(raci) == 0 {
		t.Error("expected RACI entries")
	}
}

func TestSeverityToRisk(t *testing.T) {
	cases := map[string]RiskLevel{
		"CRITICAL": "CRITICAL",
		"HIGH":     "HIGH",
		"MEDIUM":   "MEDIUM",
		"LOW":      "LOW",
	}
	for sev, want := range cases {
		got := severityToRisk(sev)
		if got != want {
			t.Errorf("severityToRisk(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestDueDateBySev(t *testing.T) {
	now := time.Now()
	cases := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, sev := range cases {
		due := dueDateBySev(sev)
		if !due.After(now) {
			t.Errorf("due date for %s should be in future", sev)
		}
	}
}

func TestCapInt2(t *testing.T) {
	if capInt2(5, 10) != 5 {
		t.Error("capInt2(5,10) should return 5")
	}
	if capInt2(15, 10) != 10 {
		t.Error("capInt2(15,10) should return 10")
	}
	if capInt2(-1, 10) != -1 {
		t.Error("capInt2(-1,10) should return -1")
	}
}

func TestMax0(t *testing.T) {
	if max0(5) != 5 {
		t.Error("max0(5) should be 5")
	}
	if max0(-1) != 0 {
		t.Error("max0(-1) should be 0")
	}
	if max0(0) != 0 {
		t.Error("max0(0) should be 0")
	}
}
