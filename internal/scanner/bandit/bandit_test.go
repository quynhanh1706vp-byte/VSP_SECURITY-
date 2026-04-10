package bandit

import (
	"context"
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

func TestParse_Empty(t *testing.T) {
	findings, err := parse([]byte(`{"results":[]}`))
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParse_SingleFinding(t *testing.T) {
	input := []byte(`{
		"results": [{
			"test_id": "B101",
			"test_name": "assert_used",
			"issue_severity": "LOW",
			"issue_text": "Use of assert detected.",
			"filename": "app/main.py",
			"line_number": 42,
			"issue_cwe": {"id": 703}
		}]
	}`)

	findings, err := parse(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "B101" {
		t.Errorf("RuleID: got %q want %q", f.RuleID, "B101")
	}
	if f.Severity != "LOW" {
		t.Errorf("Severity: got %q want %q", f.Severity, "LOW")
	}
	if f.Path != "app/main.py" {
		t.Errorf("Path: got %q want %q", f.Path, "app/main.py")
	}
	if f.Line != 42 {
		t.Errorf("LineNum: got %d want %d", f.Line, 42)
	}
}

func TestParse_MultipleSeverities(t *testing.T) {
	input := []byte(`{
		"results": [
			{"test_id":"B101","issue_severity":"LOW","issue_text":"low","filename":"a.py","line_number":1,"issue_cwe":{"id":0}},
			{"test_id":"B102","issue_severity":"MEDIUM","issue_text":"med","filename":"b.py","line_number":2,"issue_cwe":{"id":0}},
			{"test_id":"B103","issue_severity":"HIGH","issue_text":"high","filename":"c.py","line_number":3,"issue_cwe":{"id":0}}
		]
	}`)

	findings, err := parse(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := parse([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestAdapter_Name(t *testing.T) {
	a := New()
	if a.Name() != "bandit" {
		t.Errorf("expected bandit, got %q", a.Name())
	}
}

func TestAdapter_RunNoSrc(t *testing.T) {
	a := New()
	_, err := a.Run(context.TODO(), scanner.RunOpts{})
	if err == nil {
		t.Error("expected error when Src is empty")
	}
}
