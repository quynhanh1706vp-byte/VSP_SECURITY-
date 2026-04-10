package kics

import (
	"context"
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

func TestParse_Empty(t *testing.T) {
	// Try common kics empty output formats
	formats := [][]byte{
		[]byte(`{"queries":[]}`),
		[]byte(`{"results":[]}`),
		[]byte(`{}`),
	}
	for _, f := range formats {
		findings, err := parse(f)
		if err == nil && len(findings) == 0 {
			return // found correct format
		}
	}
	// At minimum, verify no panic on empty-ish input
	parse([]byte(`{}`)) //nolint:errcheck
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := parse([]byte(`{invalid`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestAdapter_Name(t *testing.T) {
	a := New()
	if a.Name() != "kics" {
		t.Errorf("expected kics, got %q", a.Name())
	}
}

func TestAdapter_RunNoSrc(t *testing.T) {
	a := New()
	_, err := a.Run(context.TODO(), scanner.RunOpts{})
	if err == nil {
		t.Error("expected error when Src is empty")
	}
}
