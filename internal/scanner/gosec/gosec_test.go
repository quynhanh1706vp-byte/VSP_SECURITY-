package gosec

import (
	"testing"
)

func TestAdapter_Name(t *testing.T) {
	if got := New().Name(); got != "gosec" {
		t.Errorf("Name() = %q, want %q", got, "gosec")
	}
}

// TestParse verifies the parser handles real gosec JSON output,
// including the quirk that line/column/cwe.id are strings (not ints).
func TestParse_RealOutput(t *testing.T) {
	raw := []byte(`{
		"Golang errors": {},
		"Issues": [
			{
				"severity": "MEDIUM",
				"confidence": "HIGH",
				"cwe": {"id": "22", "url": "https://cwe.mitre.org/data/definitions/22.html"},
				"rule_id": "G304",
				"details": "Potential file inclusion via variable",
				"file": "/repo/internal/api/middleware/csp.go",
				"code": "83: // Reload\n84: raw, err := os.ReadFile(path)\n",
				"line": "84",
				"column": "14",
				"nosec": false,
				"suppressions": null,
				"autofix": "Consider using os.Root to scope file access"
			}
		],
		"Stats": {"files": 5, "lines": 506, "nosec": 1, "found": 1},
		"GosecVersion": "dev"
	}`)

	findings, err := parse(raw)
	if err != nil {
		t.Fatalf("parse() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Tool != "gosec" {
		t.Errorf("Tool = %q, want gosec", f.Tool)
	}
	if f.RuleID != "G304" {
		t.Errorf("RuleID = %q, want G304", f.RuleID)
	}
	if f.Line != 84 {
		t.Errorf("Line = %d, want 84 (string-to-int parse)", f.Line)
	}
	if f.CWE != "CWE-22" {
		t.Errorf("CWE = %q, want CWE-22", f.CWE)
	}
	if f.FixSignal == "" {
		t.Error("FixSignal should contain autofix hint")
	}
}

func TestParse_EmptyIssues(t *testing.T) {
	raw := []byte(`{"Golang errors":{},"Issues":[],"Stats":{"files":1,"lines":10,"nosec":0,"found":0}}`)
	findings, err := parse(raw)
	if err != nil {
		t.Fatalf("parse() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := parse([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
