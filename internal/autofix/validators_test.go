// =====================================================================
// H3.Q Fix Validation Pipeline — Tests
// File: internal/autofix/validators_test.go
// Run: cd internal/autofix && go test -v -run TestH3Q
// =====================================================================

package autofix

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ───────────────────────────────────────────────────────────────────
// LineScopeValidator
// ───────────────────────────────────────────────────────────────────

func TestH3Q_LineScope_Pass(t *testing.T) {
	v := &LineScopeValidator{MaxLineDelta: 5}
	c := &FixCandidate{
		OriginalCode:   "line1\nline2\nVULN_HERE\nline4\nline5",
		SuggestedCode:  "line1\nline2\nFIX_HERE\nline4\nline5",
		VulnerableLine: 3,
	}
	r := v.Run(context.Background(), c)
	if r.Status != StatusPass {
		t.Fatalf("expected pass, got %s err=%s", r.Status, r.ErrorMsg)
	}
}

func TestH3Q_LineScope_FailIdentical(t *testing.T) {
	v := &LineScopeValidator{}
	c := &FixCandidate{
		OriginalCode:  "same\ncode",
		SuggestedCode: "same\ncode",
	}
	r := v.Run(context.Background(), c)
	if r.Status != StatusFail {
		t.Fatalf("identical fix should fail, got %s", r.Status)
	}
}

func TestH3Q_LineScope_FailOutOfWindow(t *testing.T) {
	v := &LineScopeValidator{MaxLineDelta: 2}
	c := &FixCandidate{
		OriginalCode:   "L1\nL2\nL3\nL4\nL5\nL6\nL7\nL8\nL9\nL10",
		SuggestedCode:  "DIFF\nL2\nL3\nL4\nL5\nL6\nL7\nL8\nL9\nL10",
		VulnerableLine: 8, // diff at line 1 — way outside window
	}
	r := v.Run(context.Background(), c)
	if r.Status != StatusFail {
		t.Fatalf("expected fail (out-of-window), got %s err=%s", r.Status, r.ErrorMsg)
	}
}

func TestH3Q_LineScope_FailMassiveExpansion(t *testing.T) {
	v := &LineScopeValidator{}
	orig := "L1\nL2\nL3"
	fix := strings.Repeat("L\n", 200)
	c := &FixCandidate{OriginalCode: orig, SuggestedCode: fix, VulnerableLine: 1}
	r := v.Run(context.Background(), c)
	if r.Status != StatusFail {
		t.Fatalf("massive expansion should fail, got %s", r.Status)
	}
}

// ───────────────────────────────────────────────────────────────────
// LintValidator — regression detection
// ───────────────────────────────────────────────────────────────────

func TestH3Q_Lint_FailHardcodedSecret(t *testing.T) {
	v := NewLintValidator()
	c := &FixCandidate{
		RuleID:        "secrets/generic-api-key",
		SuggestedCode: "api_key = \"sk_" + "live_abc123def456ghi789jkl012mno\"",
	}
	r := v.Run(context.Background(), c)
	if r.Status != StatusFail {
		t.Fatalf("hardcoded key should fail lint, got %s", r.Status)
	}
}

func TestH3Q_Lint_PassEnvVar(t *testing.T) {
	v := NewLintValidator()
	c := &FixCandidate{
		RuleID:        "secrets/generic-api-key",
		SuggestedCode: `api_key = os.Getenv("API_KEY")`,
	}
	r := v.Run(context.Background(), c)
	if r.Status != StatusPass {
		t.Fatalf("env var should pass, got %s err=%s", r.Status, r.ErrorMsg)
	}
}

func TestH3Q_Lint_FailS3PublicACL(t *testing.T) {
	v := NewLintValidator()
	c := &FixCandidate{
		RuleID: "kics/s3-public-acl",
		SuggestedCode: `resource "aws_s3_bucket_acl" "x" {
  acl = "public-read"
}`,
	}
	r := v.Run(context.Background(), c)
	if r.Status != StatusFail {
		t.Fatalf("public-read ACL should fail, got %s", r.Status)
	}
}

func TestH3Q_Lint_PassPrivateACL(t *testing.T) {
	v := NewLintValidator()
	c := &FixCandidate{
		RuleID: "kics/s3-public-acl",
		SuggestedCode: `resource "aws_s3_bucket_acl" "x" {
  acl = "private"
}`,
	}
	r := v.Run(context.Background(), c)
	if r.Status != StatusPass {
		t.Fatalf("private ACL should pass, got %s", r.Status)
	}
}

func TestH3Q_Lint_SkipUnknownRule(t *testing.T) {
	v := NewLintValidator()
	c := &FixCandidate{RuleID: "unknown-rule-xyz", SuggestedCode: "anything"}
	r := v.Run(context.Background(), c)
	if r.Status != StatusSkip {
		t.Fatalf("unknown rule should skip, got %s", r.Status)
	}
}

// ───────────────────────────────────────────────────────────────────
// ASTDiffValidator
// ───────────────────────────────────────────────────────────────────

func TestH3Q_ASTDiff_FailUnbalancedBraces(t *testing.T) {
	v := &ASTDiffValidator{}
	c := &FixCandidate{
		Language:      "go",
		OriginalCode:  `package x; func a() {}`,
		SuggestedCode: `package x; func a() { if true {`,
	}
	r := v.Run(context.Background(), c)
	if r.Status != StatusFail {
		t.Fatalf("unbalanced should fail, got %s", r.Status)
	}
}

func TestH3Q_ASTDiff_PassBalanced(t *testing.T) {
	v := &ASTDiffValidator{}
	c := &FixCandidate{
		Language:      "go",
		OriginalCode:  `package x; func a() { return }`,
		SuggestedCode: `package x; func a() { return nil }`,
	}
	r := v.Run(context.Background(), c)
	if r.Status != StatusPass {
		t.Fatalf("balanced should pass, got %s err=%s", r.Status, r.ErrorMsg)
	}
}

// ───────────────────────────────────────────────────────────────────
// IdempotentValidator
// ───────────────────────────────────────────────────────────────────

func TestH3Q_Idempotent_Pass(t *testing.T) {
	v := &IdempotentValidator{}
	c := &FixCandidate{SuggestedCode: "any code here"}
	r := v.Run(context.Background(), c)
	if r.Status != StatusPass {
		t.Fatalf("expected pass, got %s", r.Status)
	}
}

// ───────────────────────────────────────────────────────────────────
// Aggregate scoring + confidence gate
// ───────────────────────────────────────────────────────────────────

func TestH3Q_Aggregate_AllPass(t *testing.T) {
	results := []ValidationResult{
		{Validator: "lint", Status: StatusPass},
		{Validator: "syntax", Status: StatusPass},
		{Validator: "line_scope", Status: StatusPass},
		{Validator: "ast_diff", Status: StatusPass},
		{Validator: "idempotent", Status: StatusPass},
		{Validator: "compile", Status: StatusPass},
	}
	status, score := aggregateStatus(results)
	if status != "pass" || score != 100 {
		t.Fatalf("expected pass/100, got %s/%d", status, score)
	}
}

func TestH3Q_Aggregate_LintFail(t *testing.T) {
	results := []ValidationResult{
		{Validator: "lint", Status: StatusFail},
		{Validator: "syntax", Status: StatusPass},
		{Validator: "line_scope", Status: StatusPass},
	}
	status, score := aggregateStatus(results)
	if status == "pass" {
		t.Fatalf("lint fail should not yield pass; got %s/%d", status, score)
	}
}

func TestH3Q_ConfidenceGate(t *testing.T) {
	cases := []struct {
		in     string
		status string
		score  int
		want   string
	}{
		{"high", "pass", 95, "high"},
		{"high", "pass", 85, "medium"},
		{"high", "partial", 75, "medium"},
		{"high", "fail", 30, "low"},
		{"medium", "pass", 92, "medium"},
		{"medium", "partial", 70, "low"},
		{"low", "pass", 95, "low"},
		{"", "pass", 95, "medium"},
	}
	for _, tc := range cases {
		got := applyConfidenceGate(tc.in, tc.status, tc.score)
		if got != tc.want {
			t.Errorf("gate(%q,%s,%d): got %q want %q",
				tc.in, tc.status, tc.score, got, tc.want)
		}
	}
}

// ───────────────────────────────────────────────────────────────────
// Pipeline integration (no DB)
// ───────────────────────────────────────────────────────────────────

func TestH3Q_Pipeline_RejectsBadFix(t *testing.T) {
	p := &Pipeline{
		Validators: []Validator{
			&LineScopeValidator{},
			NewLintValidator(),
		},
	}
	c := &FixCandidate{
		CacheKey:       "test-key-" + strings.Repeat("a", 50),
		FindingID:      "00000000-0000-0000-0000-000000000001",
		Language:       "terraform",
		RuleID:         "kics/s3-public-acl",
		OriginalCode:   `resource "aws_s3_bucket_acl" "x" { acl = "public-read" }`,
		SuggestedCode:  `resource "aws_s3_bucket_acl" "x" { acl = "public-read-write" }`, // STILL public!
		VulnerableLine: 1,
		ConfidenceIn:   "high",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pr, _ := p.Run(ctx, c)
	if pr.OverallStatus == "pass" {
		t.Fatal("regressed fix should not pass")
	}
	if pr.ConfidenceFinal != "low" {
		t.Fatalf("failed fix should downgrade to low, got %s", pr.ConfidenceFinal)
	}

	gate := DefaultGate()
	ok, reason := gate.ShouldCache(pr)
	if ok {
		t.Fatalf("regressed fix should NOT be cached")
	}
	if !strings.Contains(reason, "lint") {
		t.Logf("reason: %s", reason)
	}
}

func TestH3Q_Pipeline_AcceptsGoodFix(t *testing.T) {
	p := &Pipeline{
		Validators: []Validator{
			&LineScopeValidator{},
			NewLintValidator(),
			&IdempotentValidator{},
		},
	}
	c := &FixCandidate{
		CacheKey:       "good-test-" + strings.Repeat("b", 50),
		FindingID:      "00000000-0000-0000-0000-000000000002",
		Language:       "terraform",
		RuleID:         "kics/s3-public-acl",
		OriginalCode:   `resource "aws_s3_bucket_acl" "x" { acl = "public-read" }`,
		SuggestedCode:  `resource "aws_s3_bucket_acl" "x" { acl = "private" }`,
		VulnerableLine: 1,
		ConfidenceIn:   "high",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pr, _ := p.Run(ctx, c)
	if pr.OverallStatus != "pass" {
		t.Fatalf("good fix should pass, got %s score=%d", pr.OverallStatus, pr.Score)
	}
	if pr.Score < 90 {
		t.Fatalf("good fix should score≥90, got %d", pr.Score)
	}

	gate := DefaultGate()
	ok, reason := gate.ShouldCache(pr)
	if !ok {
		t.Fatalf("good fix should be cached, rejected: %s", reason)
	}
}
