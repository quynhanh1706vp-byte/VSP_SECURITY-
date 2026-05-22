package osvscanner

import (
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

const sampleOSV = `{
  "results": [
    {
      "source": {"path": "go.mod", "type": "lockfile"},
      "packages": [
        {
          "package": {"name": "golang.org/x/net", "version": "v0.17.0", "ecosystem": "Go"},
          "vulnerabilities": [
            {
              "id": "GHSA-qppj-fm5r-hxr3",
              "summary": "HTTP/2 rapid reset attack",
              "aliases": ["CVE-2023-44487"],
              "database_specific": {"severity": "HIGH"}
            }
          ]
        }
      ]
    }
  ]
}`

func TestParseOSV(t *testing.T) {
	findings, err := parse([]byte(sampleOSV))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Tool != "osv-scanner" {
		t.Errorf("wrong tool: %s", f.Tool)
	}
	if f.Severity != scanner.SevHigh {
		t.Errorf("expected HIGH, got %s", f.Severity)
	}
	if f.CWE != "CVE-2023-44487" {
		t.Errorf("expected CVE alias, got %s", f.CWE)
	}
	if f.Category != scanner.SourceSCA {
		t.Errorf("expected SCA, got %s", f.Category)
	}
}

func TestAdapterName(t *testing.T) {
	if New().Name() != "osv-scanner" {
		t.Error("wrong name")
	}
}

func TestEmptyResults(t *testing.T) {
	findings, err := parse([]byte(`{"results":[]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0, got %d", len(findings))
	}
}

func TestSeverityMapping(t *testing.T) {
	cases := map[string]scanner.Severity{
		"CRITICAL": scanner.SevCritical,
		"HIGH":     scanner.SevHigh,
		"MEDIUM":   scanner.SevMedium,
		"MODERATE": scanner.SevMedium,
		"LOW":      scanner.SevLow,
		"":         scanner.SevMedium,
		"UNKNOWN":  scanner.SevMedium,
	}
	for input, want := range cases {
		if got := mapSeverity(input); got != want {
			t.Errorf("mapSeverity(%q) = %s, want %s", input, got, want)
		}
	}
}
