package codeql

import (
	"os"
	"path/filepath"
	"context"
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

func TestDetectLang_Python(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('hello')"), 0644) //nolint:errcheck
	lang := detectLang(dir)
	if lang != "python" {
		t.Errorf("expected python, got %q", lang)
	}
}

func TestDetectLang_Go(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0644) //nolint:errcheck
	lang := detectLang(dir)
	if lang != "go" {
		t.Errorf("expected go, got %q", lang)
	}
}

func TestDetectLang_JavaScript(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log(1)"), 0644) //nolint:errcheck
	lang := detectLang(dir)
	if lang != "javascript" {
		t.Errorf("expected javascript, got %q", lang)
	}
}

func TestDetectLang_Empty(t *testing.T) {
	dir := t.TempDir()
	lang := detectLang(dir)
	if lang != "" {
		t.Errorf("expected empty for no files, got %q", lang)
	}
}

func TestParse_Empty(t *testing.T) {
	findings, err := parseSARIF([]byte(`{"runs":[]}`), "go")
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0, got %d", len(findings))
	}
}

func TestParse_SingleResult(t *testing.T) {
	input := []byte(`{
		"runs": [{
			"results": [{
				"ruleId": "py/sql-injection",
				"level": "error",
				"message": {"text": "SQL injection vulnerability"},
				"locations": [{
					"physicalLocation": {
						"artifactLocation": {"uri": "app/db.py"},
						"region": {"startLine": 42}
					}
				}]
			}]
		}]
	}`)

	findings, err := parseSARIF(input, "python")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "py/sql-injection" {
		t.Errorf("RuleID: got %q want py/sql-injection", f.RuleID)
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := parseSARIF([]byte(`{bad`), "go")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestAdapter_Name(t *testing.T) {
	a := New()
	if a.Name() != "codeql" {
		t.Errorf("expected codeql, got %q", a.Name())
	}
}

func TestAdapter_RunNoSrc(t *testing.T) {
	a := New()
	_, err := a.Run(context.TODO(), scanner.RunOpts{})
	if err == nil {
		t.Error("expected error when Src is empty")
	}
}
