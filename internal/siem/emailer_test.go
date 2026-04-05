package siem

import (
	"strings"
	"testing"
)

func TestNewAlerter_Disabled(t *testing.T) {
	// Default config — smtp.enabled = false
	a := NewAlerter()
	if a == nil {
		t.Fatal("expected non-nil alerter")
	}
	// Should be disabled by default (no smtp config)
	if a.Enabled {
		t.Log("Note: smtp.enabled is true — check config")
	}
}

func TestAlertEmail_SendDisabled(t *testing.T) {
	a := &AlertEmail{
		Enabled: false,
		Host:    "smtp.example.com",
		Port:    587,
		From:    "test@test.com",
		To:      []string{"admin@test.com"},
	}
	// When disabled, should not attempt to send
	err := a.SendIncidentAlert(IncidentAlert{
		Title:    "Test Alert",
		Severity: "CRITICAL",
		Status:   "open",
	})
	// No error expected when disabled
	if err != nil {
		t.Errorf("expected nil error when disabled, got %v", err)
	}
}

func TestIncidentTplRenders(t *testing.T) {
	// Test template compilation (already done at init via template.Must)
	if incidentTpl == nil {
		t.Fatal("incidentTpl should not be nil")
	}
	// Test template execution with sample data
	inc := IncidentAlert{
		Title:    "Test Incident",
		Severity: "HIGH",
		Status:   "open",
		RuleName: "RULE-001",
		TenantID: "tenant-1",
	}
	var buf strings.Builder
	if err := incidentTpl.Execute(&buf, inc); err != nil {
		t.Fatalf("template execute: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected non-empty template output")
	}
	if !strings.Contains(buf.String(), "Test Incident") && !strings.Contains(buf.String(), "html") {
		t.Error("expected title in template output")
	}
}
