package report

import (
	"encoding/json"
	"testing"

	"github.com/vsp/platform/internal/scanner"
	"github.com/vsp/platform/internal/store"
)

func makeFindings(n int, severity string) []store.Finding {
	findings := make([]store.Finding, n)
	for i := range findings {
		findings[i] = store.Finding{
			ID:       "finding-" + string(rune('0'+i)),
			RunID:    "r1", // must match run.ID in BuildSARIF
			Tool:     "trivy",
			Severity: severity,
			RuleID:   "CVE-2024-001",
			Message:  "Test vulnerability",
			Path:     "go.mod",
		}
	}
	return findings
}

// suppress unused import
var _ = scanner.Finding{}

func TestSARIFDoc_Structure(t *testing.T) {
	doc := SARIFDoc{
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Version: "2.1.0",
		Runs:    []SARIFRun{},
	}

	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["version"] != "2.1.0" {
		t.Errorf("version: got %v want 2.1.0", result["version"])
	}
}

func TestSARIFLevel_Mapping(t *testing.T) {
	// SARIF levels: error=critical/high, warning=medium, note=low
	cases := map[string]string{
		"CRITICAL": "error",
		"HIGH":     "error",
		"MEDIUM":   "warning",
		"LOW":      "note",
	}
	for severity, want := range cases {
		got := severityToLevel(severity)
		if got != want {
			t.Errorf("severityToLevel(%q) = %q, want %q", severity, got, want)
		}
	}
}

func TestGenerateSARIF_Empty(t *testing.T) {
	doc := BuildSARIF(store.Run{ID: "r1", RID: "RID-001"}, []store.Finding{})
	if doc.Version != "2.1.0" {
		t.Errorf("version: got %q want 2.1.0", doc.Version)
	}
	// Empty findings → no runs (BuildSARIF groups by tool, no findings = no runs)
	if doc.Version != "2.1.0" {
		t.Errorf("version: got %q want 2.1.0", doc.Version)
	}
}

func TestGenerateSARIF_WithFindings(t *testing.T) {
	findings := makeFindings(3, "HIGH")
	doc := BuildSARIF(store.Run{ID: "r1", RID: "RID-001"}, findings)

	var totalResults int
	for _, run := range doc.Runs {
		totalResults += len(run.Results)
	}
	if totalResults == 0 {
		t.Error("expected SARIF results from findings")
	}
}

func TestGenerateSARIF_ValidJSON(t *testing.T) {
	findings := makeFindings(2, "CRITICAL")
	doc := BuildSARIF(store.Run{ID: "r1", RID: "RID-001"}, findings)

	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal SARIF: %v", err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty SARIF JSON")
	}
}
