package siem

import (
	"testing"
	"time"
)

func TestParseConfig_Empty(t *testing.T) {
	cfg := parseConfig("")
	if cfg == nil {
		t.Error("expected non-nil map for empty config")
	}
	if len(cfg) != 0 {
		t.Errorf("expected empty map, got %v", cfg)
	}
}

func TestParseConfig_KeyValue(t *testing.T) {
	cfg := parseConfig("channel: #alerts\ntoken: xoxb-123")
	if cfg["channel"] != "#alerts" {
		t.Errorf("channel: got %q want #alerts", cfg["channel"])
	}
	if cfg["token"] != "xoxb-123" {
		t.Errorf("token: got %q want xoxb-123", cfg["token"])
	}
}

func TestParseConfig_MultipleSpaces(t *testing.T) {
	cfg := parseConfig("key1: val1\nkey2: val2\nkey3: val3")
	if len(cfg) != 3 {
		t.Errorf("expected 3 keys, got %d: %v", len(cfg), cfg)
	}
}

func TestExpandVars_NoVars(t *testing.T) {
	rc := RunCtx{
		Gate:     "PASS",
		Score:    95,
		TenantID: "tenant-1",
	}
	result := expandVars("no variables here", rc)
	if result != "no variables here" {
		t.Errorf("expected unchanged string, got %q", result)
	}
}

func TestExpandVars_WithGate(t *testing.T) {
	rc := RunCtx{Gate: "FAIL", Score: 50, RunID: "RID-001"}
	result := expandVars("Gate: {{.Gate}} Findings: {{.Findings}}", rc)
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestParseDuration_Valid(t *testing.T) {
	cases := map[string]time.Duration{
		"duration: 30s": 30 * time.Second,
		"duration: 5m":  5 * time.Minute,
		"duration: 1h":  time.Hour,
	}
	for config, want := range cases {
		got := parseDuration(config)
		if got != want {
			t.Errorf("parseDuration(%q) = %v, want %v", config, got, want)
		}
	}
}

func TestParseDuration_Default(t *testing.T) {
	// No timeout in config → default
	got := parseDuration("channel: #alerts")
	if got <= 0 {
		t.Error("expected positive default duration")
	}
}

func TestExecCondition_AlwaysTrue(t *testing.T) {
	rc := RunCtx{Gate: "FAIL", Score: 50}
	result, err := execCondition(rc, "gate=FAIL")
	if err != nil {
		t.Fatalf("execCondition: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}
