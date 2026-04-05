package pipeline

import (
	"testing"

	"github.com/vsp/platform/internal/store"
)

func TestScannerSummaryFromStore_Empty(t *testing.T) {
	s := ScannerSummaryFromStore(&store.FindingSummary{})
	if s.Critical != 0 || s.High != 0 {
		t.Errorf("expected all zeros, got critical=%d high=%d", s.Critical, s.High)
	}
}

func TestScannerSummaryFromStore_WithData(t *testing.T) {
	fs := &store.FindingSummary{
		Critical: 2,
		High:     5,
		Medium:   10,
		Low:      3,
	}
	s := ScannerSummaryFromStore(fs)
	if s.Critical != 2 {
		t.Errorf("Critical: got %d want 2", s.Critical)
	}
	if s.High != 5 {
		t.Errorf("High: got %d want 5", s.High)
	}
	if s.Medium != 10 {
		t.Errorf("Medium: got %d want 10", s.Medium)
	}
}

func TestSeverityToPriority(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "P1",
		"HIGH":     "P2",
		"MEDIUM":   "P3",
		"LOW":      "P4",
		"INFO":     "P4",
		"UNKNOWN":  "P4",
	}
	for sev, want := range cases {
		got := severityToPriority(sev)
		if got != want {
			t.Errorf("severityToPriority(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestNewScanTask_ValidPayload(t *testing.T) {
	payload := JobPayload{
		RID:      "RID-001",
		TenantID: "tenant-1",
		Mode:     "SAST",
		Profile:  "FAST",
		Src:      "/code",
	}
	task, err := NewScanTask(payload)
	if err != nil {
		t.Fatalf("NewScanTask: %v", err)
	}
	if task == nil {
		t.Fatal("expected non-nil task")
	}
}

func TestSetBroadcast(t *testing.T) {
	// Should not panic
	var called bool
	SetBroadcast(func(b []byte) { called = true })
	// broadcastSSE is now set — verify no panic on nil-safe call
	_ = called
}
