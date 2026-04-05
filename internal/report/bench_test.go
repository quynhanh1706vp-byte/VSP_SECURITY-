package report

import (
	"testing"

	"github.com/vsp/platform/internal/store"
)

func BenchmarkBuildSARIF_Empty(b *testing.B) {
	run := store.Run{ID: "r1", RID: "RID-001"}
	for i := 0; i < b.N; i++ {
		_ = BuildSARIF(run, nil)
	}
}

func BenchmarkBuildSARIF_100Findings(b *testing.B) {
	run := store.Run{ID: "r1", RID: "RID-001"}
	findings := make([]store.Finding, 100)
	for i := range findings {
		findings[i] = store.Finding{
			RunID:    "r1",
			Tool:     "trivy",
			Severity: "HIGH",
			RuleID:   "CVE-2024-001",
			Message:  "test vulnerability",
			Path:     "go.mod",
		}
	}
	for i := 0; i < b.N; i++ {
		_ = BuildSARIF(run, findings)
	}
}

func BenchmarkSeverityToLevel(b *testing.B) {
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	for i := 0; i < b.N; i++ {
		_ = severityToLevel(severities[i%len(severities)])
	}
}
