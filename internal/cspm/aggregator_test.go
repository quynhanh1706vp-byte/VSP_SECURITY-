package cspm

import (
	"context"
	"testing"
)

func TestDetectProvider(t *testing.T) {
	tests := map[string]CloudProvider{
		"aws_s3_bucket":      AWS,
		"google_storage":     GCP,
		"azurerm_storage":    Azure,
		"kubernetes_pod":     K8s,
		"docker_container":   Other,
	}
	for input, expected := range tests {
		got := DetectProvider(input)
		if got != expected {
			t.Errorf("DetectProvider(%s) = %s, want %s", input, got, expected)
		}
	}
}

func TestScore_AllPass(t *testing.T) {
	a := New([]Finding{})
	scores := a.Score(context.Background())
	if len(scores) != 0 {
		t.Errorf("expected 0 scores for empty findings, got %d", len(scores))
	}
}

func TestScore_AWSCritical(t *testing.T) {
	a := New([]Finding{
		{Tool: "kics", Severity: "critical", Provider: AWS, RuleID: "CKV_AWS_18", Message: "S3 public access"},
		{Tool: "kics", Severity: "high", Provider: AWS, RuleID: "CKV_AWS_19", Message: "Encryption disabled"},
		{Tool: "checkov", Severity: "medium", Provider: AWS, RuleID: "CKV_AWS_57", Message: "Logging missing"},
	})
	scores := a.Score(context.Background())
	if len(scores) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(scores))
	}
	if scores[0].Critical != 1 || scores[0].High != 1 || scores[0].Medium != 1 {
		t.Errorf("severity counts wrong: %+v", scores[0])
	}
	if scores[0].Score >= 100 {
		t.Errorf("expected score < 100 with critical findings, got %.1f", scores[0].Score)
	}
}
