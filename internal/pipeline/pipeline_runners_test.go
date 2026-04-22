package pipeline

import (
	"testing"
)

func TestRunnersFor_SAST(t *testing.T) {
	runners := RunnersFor(ModeSAST)
	if len(runners) == 0 {
		t.Error("expected runners for SAST mode")
	}
}

func TestRunnersFor_Secrets(t *testing.T) {
	runners := RunnersFor(ModeSecrets)
	if len(runners) == 0 {
		t.Error("expected runners for SECRETS mode")
	}
}

func TestRunnersFor_Full(t *testing.T) {
	runners := RunnersFor(ModeFull)
	if len(runners) == 0 {
		t.Error("expected runners for FULL mode")
	}
	// FULL should have more runners than SAST
	sastRunners := RunnersFor(ModeSAST)
	if len(runners) < len(sastRunners) {
		t.Errorf("FULL should have >= runners than SAST: full=%d sast=%d", len(runners), len(sastRunners))
	}
}

func TestRunnersFor_SCA(t *testing.T) {
	runners := RunnersFor(ModeSCA)
	if len(runners) == 0 {
		t.Error("expected runners for SCA mode")
	}
}

func TestRunnersFor_AllModes(t *testing.T) {
	modes := []Mode{ModeSAST, ModeDAST, ModeSCA, ModeSecrets, ModeIAC, ModeFull}
	for _, mode := range modes {
		runners := RunnersFor(mode)
		t.Logf("Mode %s: %d runners", mode, len(runners))
	}
}

// TestRunnersFor_FullSOC verifies FULL_SOC mode returns all unique tools
// from SAST+SCA+SECRETS+IAC+DAST+NETWORK (sslscan deduplicated).
//
// Regression test for BUG-019 (FULL_SOC mode never triggered any runs because
// RunnersFor had no case for it, causing pipeline to return the default fallback).
func TestRunnersFor_FullSOC(t *testing.T) {
	runners := RunnersFor(ModeFullSOC)
	if len(runners) == 0 {
		t.Fatal("expected runners for FULL_SOC mode")
	}

	// FULL_SOC must include at least as many runners as FULL
	fullRunners := RunnersFor(ModeFull)
	if len(runners) < len(fullRunners) {
		t.Errorf("FULL_SOC should have >= runners than FULL: full_soc=%d full=%d",
			len(runners), len(fullRunners))
	}

	// No duplicate tool names
	seen := make(map[string]bool)
	for _, r := range runners {
		if seen[r.Name()] {
			t.Errorf("duplicate runner in FULL_SOC: %s", r.Name())
		}
		seen[r.Name()] = true
	}
}

// TestRunnersFor_NetworkMode verifies NETWORK mode contains the expected
// baseline tools (sslscan + nmap). Netcap is conditional on engine being
// wired — when nil (default in tests), it's omitted cleanly.
//
// Regression test for BUG-020 (nmap was originally in DAST, netcap not
// registered at all despite being listed in docs/FEATURE_INVENTORY.md).
func TestRunnersFor_NetworkMode(t *testing.T) {
	runners := RunnersFor(ModeNetwork)
	if len(runners) < 2 {
		t.Fatalf("NETWORK should have at least sslscan + nmap, got %d", len(runners))
	}
	names := map[string]bool{}
	for _, r := range runners {
		names[r.Name()] = true
	}
	for _, must := range []string{"sslscan", "nmap"} {
		if !names[must] {
			t.Errorf("NETWORK missing expected runner: %s", must)
		}
	}
	// netcap should NOT be present when engine is nil (test default)
	if names["netcap"] {
		t.Error("netcap should be absent when netcapEngine is nil")
	}
}

// TestRunnersFor_DASTWithoutNmap verifies nmap is no longer in DAST after
// regrouping per docs spec §8.1 (nmap belongs to NETWORK).
func TestRunnersFor_DASTWithoutNmap(t *testing.T) {
	runners := RunnersFor(ModeDAST)
	for _, r := range runners {
		if r.Name() == "nmap" {
			t.Error("nmap should no longer be in DAST — it belongs to NETWORK per FEATURE_INVENTORY.md §8.1")
		}
	}
}

// TestRunnersFor_FullIncludesNetworkTools verifies FULL mode aggregates
// tools from ALL groups including NETWORK, not just sast+sca+secrets+iac+dast.
//
// Regression test for BUG-021 (post-PR#53 regression): after nmap was
// moved from DAST to NETWORK, the FULL case in RunnersFor kept iterating
// only the original 5 groups, silently dropping nmap + netcap from FULL.
func TestRunnersFor_FullIncludesNetworkTools(t *testing.T) {
	runners := RunnersFor(ModeFull)
	names := map[string]bool{}
	for _, r := range runners {
		names[r.Name()] = true
	}

	// nmap must be in FULL — it's a core NETWORK scanner
	if !names["nmap"] {
		t.Error("FULL mode missing nmap (regression from BUG-021)")
	}

	// sslscan dedup check — DAST has it, NETWORK has it too.
	// Should appear exactly once in FULL (not dropped, not duplicated).
	sslCount := 0
	for _, r := range runners {
		if r.Name() == "sslscan" {
			sslCount++
		}
	}
	if sslCount != 1 {
		t.Errorf("sslscan should appear exactly 1 time in FULL (dedup), got %d", sslCount)
	}
}

// TestRunnersFor_FullSOCMatchesFull — currently FULL_SOC has no extra tools
// beyond FULL; SOC-level enrichment is downstream post-processing.
// This test documents that invariant — changing it requires updating the
// tool count metadata in internal/api/handler/runs.go toolsTotal map.
func TestRunnersFor_FullSOCMatchesFull(t *testing.T) {
	full := RunnersFor(ModeFull)
	soc := RunnersFor(ModeFullSOC)
	if len(full) != len(soc) {
		t.Errorf("FULL=%d vs FULL_SOC=%d — if intentional, update toolsTotal map and this test",
			len(full), len(soc))
	}
}
