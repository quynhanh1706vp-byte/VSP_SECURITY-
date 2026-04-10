package nuclei

import (
	"context"
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

func TestAdapter_Name(t *testing.T) {
	a := New()
	if a.Name() != "nuclei" {
		t.Errorf("expected nuclei, got %q", a.Name())
	}
}

func TestAdapter_RunNoURL(t *testing.T) {
	a := New()
	_, err := a.Run(context.TODO(), scanner.RunOpts{})
	if err == nil {
		t.Error("expected error when URL/Src empty")
	}
}
