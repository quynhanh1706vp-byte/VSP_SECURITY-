package gitleaks

import (
	"context"
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

func TestParse_Empty(t *testing.T) {
	findings, err := parse([]byte(`[]`))
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParse_SingleLeak(t *testing.T) {
	input := []byte(`[{
		"Description": "AWS Access Key",
		"StartLine": 10,
		"File": ".env",
		"RuleID": "aws-access-token",
		"Secret": "AKIAIOSFODNN7EXAMPLE",
		"Match": "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
	}]`)

	findings, err := parse(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != "CRITICAL" {
		t.Errorf("secrets should be CRITICAL, got %q", f.Severity)
	}
	if f.Path != ".env" {
		t.Errorf("Path: got %q want %q", f.Path, ".env")
	}
	if f.RuleID != "aws-access-token" {
		t.Errorf("RuleID: got %q want %q", f.RuleID, "aws-access-token")
	}
	if f.Line != 10 {
		t.Errorf("LineNum: got %d want %d", f.Line, 10)
	}
}

func TestParse_MultipleLeaks(t *testing.T) {
	input := []byte(`[
		{"Description":"Secret 1","StartLine":1,"File":"a.env","RuleID":"rule-1","Secret":"s1","Match":"m1"},
		{"Description":"Secret 2","StartLine":2,"File":"b.env","RuleID":"rule-2","Secret":"s2","Match":"m2"}
	]`)

	findings, err := parse(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := parse([]byte(`not valid json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestAdapter_Name(t *testing.T) {
	a := New()
	if a.Name() != "gitleaks" {
		t.Errorf("expected gitleaks, got %q", a.Name())
	}
}

func TestAdapter_RunNoSrc(t *testing.T) {
	a := New()
	_, err := a.Run(context.TODO(), scanner.RunOpts{})
	if err == nil {
		t.Error("expected error when Src is empty")
	}
}
