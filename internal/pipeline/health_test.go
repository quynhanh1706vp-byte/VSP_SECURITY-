package pipeline

import (
	"testing"
)

// TestHealthSnapshot_ReturnsExpected26 pins the 26-tool registry shape
// regardless of which binaries are actually on the test runner's $PATH.
// The "available" count varies by host; what matters is that the
// snapshot enumerates exactly the 26 tools (25 in scannerBinaries +
// netcap), so the FE "X / 26 ready" badge always has a stable
// denominator.
func TestHealthSnapshot_ReturnsExpected26(t *testing.T) {
	_, results := HealthSnapshot()
	if len(results) != 26 {
		t.Fatalf("HealthSnapshot returned %d tools, expected 26 "+
			"(if the registry changed, update ToolNamesForMode + "+
			"runs_enqueue_test.go + this test together)", len(results))
	}

	// Every tool name must be non-empty (defensive — empty would
	// break the FE rendering).
	seen := map[string]bool{}
	for _, r := range results {
		if r.Tool == "" {
			t.Errorf("empty Tool name in snapshot row: %+v", r)
		}
		if seen[r.Tool] {
			t.Errorf("duplicate tool %q in snapshot", r.Tool)
		}
		seen[r.Tool] = true
	}

	// netcap is special — it must always be present in the snapshot
	// even when no engine is registered (the FE shows it as "absent").
	if !seen["netcap"] {
		t.Error("snapshot missing netcap entry")
	}
}

// TestHealthSnapshot_NetcapEngineGate verifies the netcap row reflects
// engine registration. We don't register an engine in this test, so it
// should be Available=false.
func TestHealthSnapshot_NetcapEngineGate(t *testing.T) {
	_, results := HealthSnapshot()
	for _, r := range results {
		if r.Tool == "netcap" {
			if r.Available {
				t.Error("netcap reports Available=true but no engine registered")
			}
			if !r.NetcapEngine {
				t.Error("netcap row should have NetcapEngine=true marker")
			}
			return
		}
	}
	t.Error("netcap entry not found")
}
