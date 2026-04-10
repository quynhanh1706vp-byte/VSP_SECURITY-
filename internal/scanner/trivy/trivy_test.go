package trivy

import (
	"context"
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

func TestParse_Empty(t *testing.T) {
	findings, err := parse([]byte(`{"Results":[]}`))
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParse_SingleVuln(t *testing.T) {
	input := []byte(`{
		"Results": [{
			"Target": "go.mod",
			"Type": "gomod",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2024-45337",
				"Severity": "CRITICAL",
				"Title": "PublicKeyCallback bypass",
				"InstalledVersion": "0.28.0",
				"FixedVersion": "0.31.0",
				"PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-45337"
			}]
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
	if f.RuleID != "CVE-2024-45337" {
		t.Errorf("RuleID: got %q want %q", f.RuleID, "CVE-2024-45337")
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("Severity: got %q want %q", f.Severity, "CRITICAL")
	}
}

func TestParse_MultipleResults(t *testing.T) {
	input := []byte(`{
		"Results": [
			{
				"Target": "go.mod",
				"Vulnerabilities": [
					{"VulnerabilityID":"CVE-001","Severity":"HIGH","Title":"t1","InstalledVersion":"1.0","FixedVersion":"1.1"},
					{"VulnerabilityID":"CVE-002","Severity":"MEDIUM","Title":"t2","InstalledVersion":"2.0","FixedVersion":"2.1"}
				]
			},
			{
				"Target": "requirements.txt",
				"Vulnerabilities": [
					{"VulnerabilityID":"CVE-003","Severity":"LOW","Title":"t3","InstalledVersion":"3.0","FixedVersion":""}
				]
			}
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

func TestParse_NullVulnerabilities(t *testing.T) {
	input := []byte(`{"Results":[{"Target":"clean.go","Vulnerabilities":null}]}`)
	findings, err := parse(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for null vulns, got %d", len(findings))
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := parse([]byte(`{bad json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestAdapter_Name(t *testing.T) {
	a := New()
	if a.Name() != "trivy" {
		t.Errorf("expected trivy, got %q", a.Name())
	}
}

func TestAdapter_RunNoSrc(t *testing.T) {
	a := New()
	_, err := a.Run(context.TODO(), scanner.RunOpts{})
	if err == nil {
		t.Error("expected error when Src is empty")
	}
}
