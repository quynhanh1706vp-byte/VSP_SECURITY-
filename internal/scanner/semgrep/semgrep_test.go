package semgrep

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
			"check_id": "python.flask.security.unescaped-template-extension.unescaped-template-extension",
			"path": "app/views.py",
			"start": {"line": 25},
			"extra": {
				"message": "Template extension not escaped",
				"severity": "WARNING",
				"metadata": {"cwe": ["CWE-79"]}
			}
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
	if f.Path != "app/views.py" {
		t.Errorf("Path: got %q want app/views.py", f.Path)
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
	if a.Name() != "semgrep" {
		t.Errorf("expected semgrep, got %q", a.Name())
	}
}

func TestAdapter_RunNoSrc(t *testing.T) {
	a := New()
	_, err := a.Run(context.TODO(), scanner.RunOpts{})
	if err == nil {
		t.Error("expected error when Src is empty")
	}
}
