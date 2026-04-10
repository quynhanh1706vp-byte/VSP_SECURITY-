package siem

import (
	"testing"
	"time"
)

func TestCorrelatorState_CanFire(t *testing.T) {
	s := newCorrelatorState()

	// First fire should be allowed
	if !s.canFire("rule-1", 30) {
		t.Error("first fire should be allowed")
	}

	// Immediate second fire should be blocked (within window)
	if s.canFire("rule-1", 30) {
		t.Error("second immediate fire should be blocked")
	}

	// Different rule should be allowed
	if !s.canFire("rule-2", 30) {
		t.Error("different rule should be allowed")
	}
}

func TestCorrelatorState_WindowExpiry(t *testing.T) {
	s := newCorrelatorState()

	// Fire once
	s.canFire("rule-1", 1) // 1 minute window

	// Simulate window expiry by manipulating lastFired
	s.lastFire["rule-1"] = time.Now().Add(-2 * time.Minute)

	// Should be allowed again after window
	if !s.canFire("rule-1", 1) {
		t.Error("should be allowed after window expiry")
	}
}

func TestExtractThreshold(t *testing.T) {
	cases := []struct {
		expr string
		want int
	}{
		{"count>=10", 10},
		{"count>=5", 5},
		{"count>9", 10},          // count>9 → n+1=10
		{"no threshold here", 1}, // default
	}
	for _, c := range cases {
		got := extractThreshold(c.expr)
		if got != c.want {
			t.Errorf("extractThreshold(%q) = %d, want %d", c.expr, got, c.want)
		}
	}
}

func TestSanitizeField(t *testing.T) {
	cases := map[string]string{
		"severity":  "severity",
		"source_ip": "source_ip",
		"SEVERITY":  "severity", // lowercase
		"host":      "host",
		"process":   "process",
		"unknown":   "message", // default fallback
	}
	for input, want := range cases {
		got := sanitizeField(input)
		if got != want {
			t.Errorf("sanitizeField(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSanitizeJSONKey(t *testing.T) {
	// JSON keys should be sanitized to prevent injection
	cases := []string{"severity", "source_ip", "host"}
	for _, k := range cases {
		got := sanitizeJSONKey(k)
		if got == "" {
			t.Errorf("sanitizeJSONKey(%q) returned empty", k)
		}
	}
}
