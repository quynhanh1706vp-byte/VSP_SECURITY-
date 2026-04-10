package checkov

import (
	"context"
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

func TestParse_Empty(t *testing.T) {
	findings, err := parse([]byte(`{"results":{"failed_checks":[]}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParse_SingleCheck(t *testing.T) {
	input := []byte(`{
		"results": {
			"failed_checks": [{
				"check_id": "CKV_AWS_1",
				"check_type": "terraform",
				"check_result": {"result": "FAILED"},
				"resource": "aws_s3_bucket.main",
				"file_path": "main.tf",
				"file_line_range": [1, 10],
				"severity": "HIGH"
			}]
		}
	}`)

	findings, err := parse(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "CKV_AWS_1" {
		t.Errorf("RuleID: got %q want CKV_AWS_1", f.RuleID)
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
	if a.Name() != "checkov" {
		t.Errorf("expected checkov, got %q", a.Name())
	}
}

func TestAdapter_RunNoSrc(t *testing.T) {
	a := New()
	_, err := a.Run(context.TODO(), scanner.RunOpts{})
	if err == nil {
		t.Error("expected error when Src is empty")
	}
}
