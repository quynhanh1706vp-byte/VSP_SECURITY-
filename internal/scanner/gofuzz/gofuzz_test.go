package gofuzz

import (
	"context"
	"testing"
	"time"
)

func TestDiscover_NoCrash(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	files, err := Discover(ctx, "/tmp")
	if err != nil {
		t.Fatalf("Discover error: %v", err)
	}
	_ = files
}

func TestExtractCrash(t *testing.T) {
	out := "fuzz: elapsed: 30s, gathering baseline coverage: 0/100 completed\nfailing input written to testdata/fuzz/FuzzFoo/abc123\n"
	c := extractCrash(out)
	if c == "" {
		t.Errorf("expected crash, got empty")
	}
}

// FuzzExtractCrash demonstrates a fuzz target that VSP itself can scan.
func FuzzExtractCrash(f *testing.F) {
	f.Add("normal output without crash")
	f.Add("failing input written to /tmp/crash")
	f.Fuzz(func(t *testing.T, s string) {
		_ = extractCrash(s) // should not panic
	})
}
