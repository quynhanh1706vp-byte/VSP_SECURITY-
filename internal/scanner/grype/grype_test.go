package grype

import (
	"context"
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

func TestParse_Empty(t *testing.T) {
	findings, err := parse([]byte(`{"matches":[]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0, got %d", len(findings))
	}
}

func TestParse_SingleMatch(t *testing.T) {
	input := []byte(`{
		"matches": [{
			"vulnerability": {
				"id": "CVE-2024-1234",
				"severity": "High",
				"description": "Test vulnerability",
				"fix": {"versions": ["1.2.3"], "state": "fixed"}
			},
			"artifact": {
				"name": "mypackage",
				"version": "1.0.0",
				"locations": "go.sum"
			}
		}]
	}`)
	findings, err := parse(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "CVE-2024-1234" {
		t.Errorf("RuleID: got %q want CVE-2024-1234", f.RuleID)
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := parse([]byte(`bad`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestAdapter_Name(t *testing.T) {
	a := New()
	if a.Name() != "grype" {
		t.Errorf("expected grype, got %q", a.Name())
	}
}

func TestAdapter_RunNoSrc(t *testing.T) {
	a := New()
	_, err := a.Run(context.TODO(), scanner.RunOpts{})
	if err == nil {
		t.Error("expected error when Src is empty")
	}
}
