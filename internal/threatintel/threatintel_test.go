package threatintel

import (
	"testing"
)

func TestComputeRiskScore_AllZero(t *testing.T) {
	enr := &CVEEnrichment{}
	score := computeRiskScore(enr)
	if score != 0.0 {
		t.Errorf("zero enrichment: got %v, want 0", score)
	}
}

func TestComputeRiskScore_HighCVSSOnly(t *testing.T) {
	enr := &CVEEnrichment{CVSS: 10.0}
	score := computeRiskScore(enr)
	// CVSS 10.0/10 * 35 = 35
	if score != 35.0 {
		t.Errorf("CVSS 10: got %v, want 35", score)
	}
}

func TestComputeRiskScore_HighEPSSOnly(t *testing.T) {
	enr := &CVEEnrichment{EPSS: 1.0}
	score := computeRiskScore(enr)
	// EPSS 1.0 * 35 = 35
	if score != 35.0 {
		t.Errorf("EPSS 1.0: got %v, want 35", score)
	}
}

func TestComputeRiskScore_KEVOnly(t *testing.T) {
	enr := &CVEEnrichment{KEV: true}
	score := computeRiskScore(enr)
	// KEV bonus only = 30
	if score != 30.0 {
		t.Errorf("KEV only: got %v, want 30", score)
	}
}

func TestComputeRiskScore_Critical(t *testing.T) {
	// Real-world: Log4Shell-like
	enr := &CVEEnrichment{CVSS: 10.0, EPSS: 0.97, KEV: true}
	score := computeRiskScore(enr)
	// 35 + (0.97*35) + 30 = 35 + 33.95 + 30 = 98.95
	if score < 95 || score > 100 {
		t.Errorf("Log4Shell-like: got %v, want ~99", score)
	}
}

func TestComputeRiskScore_CapsAt100(t *testing.T) {
	// Synthetic over-100 input
	enr := &CVEEnrichment{CVSS: 10.0, EPSS: 1.0, KEV: true}
	score := computeRiskScore(enr)
	// 35 + 35 + 30 = 100 (exactly)
	if score != 100.0 {
		t.Errorf("max: got %v, want 100", score)
	}
}

func TestComputeRiskScore_Medium(t *testing.T) {
	// Moderate risk
	enr := &CVEEnrichment{CVSS: 6.5, EPSS: 0.15}
	score := computeRiskScore(enr)
	// 6.5/10*35 + 0.15*35 = 22.75 + 5.25 = 28.0
	if score < 27 || score > 29 {
		t.Errorf("medium: got %v, want ~28", score)
	}
}

func TestNewClient_DefaultsValid(t *testing.T) {
	c := NewClient()
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.kevSet == nil {
		t.Error("kevSet not initialized")
	}
	if c.cache == nil {
		t.Error("cache not initialized")
	}
}

func TestClientStats_Empty(t *testing.T) {
	c := NewClient()
	stats := c.Stats()
	if stats.KEVCount != 0 {
		t.Errorf("empty KEV: got %d, want 0", stats.KEVCount)
	}
}

func TestClientStats_AfterKEVPopulation(t *testing.T) {
	c := NewClient()
	// Manually populate (simulate after LoadKEV)
	c.mu.Lock()
	c.kevSet["CVE-2024-3094"] = true
	c.kevSet["CVE-2021-44228"] = true
	c.mu.Unlock()
	stats := c.Stats()
	if stats.KEVCount != 2 {
		t.Errorf("KEVCount: got %d, want 2", stats.KEVCount)
	}
}
