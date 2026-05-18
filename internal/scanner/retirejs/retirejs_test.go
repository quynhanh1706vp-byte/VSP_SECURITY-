package retirejs

import (
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

const sampleRetire = `{
  "version": "5.4.2",
  "data": [
    {
      "file": "/static/vendor/jquery.min.js",
      "results": [
        {
          "component": "jquery",
          "version": "1.6.1",
          "vulnerabilities": [
            {
              "severity": "medium",
              "identifiers": {"CVE": ["CVE-2012-6708"], "summary": "XSS via selector"},
              "info": ["https://bugs.jquery.com/ticket/11290"],
              "summary": "XSS when parsing HTML"
            },
            {
              "severity": "high",
              "identifiers": {"CVE": ["CVE-2015-9251"]},
              "summary": "Prototype pollution"
            }
          ]
        }
      ]
    }
  ]
}`

func TestParseRetireJS(t *testing.T) {
	findings, err := parse([]byte(sampleRetire))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Tool != "retire-js" {
			t.Errorf("wrong tool: %s", f.Tool)
		}
		if f.Path != "/static/vendor/jquery.min.js" {
			t.Errorf("expected file path, got %s", f.Path)
		}
		if f.Category != scanner.SourceSCA {
			t.Errorf("expected SCA, got %s", f.Category)
		}
	}
	if findings[0].Severity != scanner.SevMedium {
		t.Errorf("first finding should be MEDIUM")
	}
	if findings[1].Severity != scanner.SevHigh {
		t.Errorf("second finding should be HIGH")
	}
	if findings[1].CWE != "CVE-2015-9251" {
		t.Errorf("expected CVE, got %s", findings[1].CWE)
	}
}

func TestAdapterName(t *testing.T) {
	if New().Name() != "retire-js" {
		t.Error("wrong name")
	}
}

func TestEmptyResults(t *testing.T) {
	findings, err := parse([]byte(`{"version":"5.4.2","data":[]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0, got %d", len(findings))
	}
}
