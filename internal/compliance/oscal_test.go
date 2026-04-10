package compliance

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vsp/platform/internal/store"
)

func makeRuns(n int) []store.Run {
	runs := make([]store.Run, n)
	now := time.Now()
	for i := range runs {
		runs[i] = store.Run{
			ID:        "run-" + string(rune('0'+i)),
			RID:       "RID-001",
			Status:    "DONE",
			Gate:      "PASS",
			CreatedAt: now,
		}
	}
	return runs
}

func makeFindings(severities ...string) []store.Finding {
	f := make([]store.Finding, len(severities))
	for i, sev := range severities {
		f[i] = store.Finding{
			ID:       "f" + string(rune('0'+i)),
			Severity: sev,
			Tool:     "trivy",
			RuleID:   "CVE-2024-000" + string(rune('0'+i)),
			Message:  "test",
			CWE:      "CWE-79",
		}
	}
	return f
}

func TestBuildAR_Empty(t *testing.T) {
	ar := BuildAR("tenant-1", []store.Run{}, []store.Finding{})
	if ar == nil {
		t.Fatal("expected non-nil AR")
	}
	if ar.UUID == "" {
		t.Error("expected non-empty UUID")
	}
}

func TestBuildAR_WithData(t *testing.T) {
	runs := makeRuns(3)
	findings := makeFindings("CRITICAL", "HIGH", "MEDIUM")
	ar := BuildAR("tenant-1", runs, findings)
	if ar == nil {
		t.Fatal("expected non-nil AR")
	}
}

func TestBuildPOAM_Empty(t *testing.T) {
	poam := BuildPOAM("tenant-1", []store.Finding{})
	if poam == nil {
		t.Fatal("expected non-nil POAM")
	}
}

func TestBuildPOAM_WithFindings(t *testing.T) {
	findings := makeFindings("CRITICAL", "HIGH", "MEDIUM", "LOW")
	poam := BuildPOAM("tenant-1", findings)
	if poam == nil {
		t.Fatal("expected non-nil POAM")
	}
	if len(poam.Items) == 0 {
		t.Error("expected POAM items from findings")
	}
}

func TestDueDays(t *testing.T) {
	cases := map[string]int{
		"CRITICAL": 3,
		"HIGH":     14,
		"MEDIUM":   30,
		"LOW":      90,
	}
	for sev, want := range cases {
		got := dueDays(sev)
		if got != want {
			t.Errorf("dueDays(%q) = %d, want %d", sev, got, want)
		}
	}
}

func TestToJSON(t *testing.T) {
	data := map[string]string{"key": "value"}
	b, err := ToJSON(data)
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	var result map[string]string
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("expected value, got %q", result["key"])
	}
}

func TestToJSON_Invalid(t *testing.T) {
	// Channel cannot be marshaled
	_, err := ToJSON(make(chan int))
	if err == nil {
		t.Error("expected error for non-marshallable type")
	}
}
