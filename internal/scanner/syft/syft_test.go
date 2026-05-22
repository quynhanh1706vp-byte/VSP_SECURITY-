package syft

import (
	"testing"
)

func TestName(t *testing.T) {
	a := New()
	if a.Name() != "syft" {
		t.Errorf("expected name 'syft', got %q", a.Name())
	}
}

func TestParseMinimal(t *testing.T) {
	input := []byte(`{
		"components": [
			{
				"type": "library",
				"name": "github.com/stretchr/testify",
				"version": "v1.8.4",
				"purl": "pkg:golang/github.com/stretchr/testify@v1.8.4",
				"licenses": [ { "license": { "id": "MIT" } } ]
			},
			{
				"type": "library",
				"name": "golang.org/x/net",
				"version": "v0.17.0",
				"purl": "pkg:golang/golang.org/x/net@v0.17.0",
				"licenses": [ { "license": { "name": "BSD-3-Clause" } } ]
			},
			{
				"type": "application",
				"name": "no-license-pkg",
				"version": "0.0.1"
			}
		]
	}`)

	findings, err := parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// First finding
	f := findings[0]
	if f.Tool != "syft" {
		t.Errorf("expected tool=syft, got %q", f.Tool)
	}
	if f.RuleID != "SBOM-COMPONENT" {
		t.Errorf("expected rule SBOM-COMPONENT, got %q", f.RuleID)
	}
	if f.Path != "github.com/stretchr/testify@v1.8.4" {
		t.Errorf("unexpected path: %q", f.Path)
	}
	if lic, _ := f.Raw["license"].(string); lic != "MIT" {
		t.Errorf("expected license MIT, got %v", f.Raw["license"])
	}

	// Second: license via Name (no ID)
	if lic, _ := findings[1].Raw["license"].(string); lic != "BSD-3-Clause" {
		t.Errorf("expected BSD-3-Clause, got %v", findings[1].Raw["license"])
	}

	// Third: no license → UNKNOWN
	if lic, _ := findings[2].Raw["license"].(string); lic != "UNKNOWN" {
		t.Errorf("expected UNKNOWN, got %v", findings[2].Raw["license"])
	}
}

func TestParseEmpty(t *testing.T) {
	findings, err := parse([]byte(`{"components":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseInvalidJSON(t *testing.T) {
	_, err := parse([]byte(`{not json`))
	if err == nil {
		t.Error("expected error on invalid json")
	}
}
