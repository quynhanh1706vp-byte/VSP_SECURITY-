package trufflehog

import (
	"testing"
)

func TestAdapter_Name(t *testing.T) {
	if got := New().Name(); got != "trufflehog" {
		t.Errorf("Name() = %q, want trufflehog", got)
	}
}

// TestParse_VerifiedAWS verifies a verified AWS credential is mapped to
// CRITICAL severity with CWE-798.
func TestParse_VerifiedAWS(t *testing.T) {
	// Sample from actual trufflehog output (github source with verified AWS key)
	raw := []byte(`{"SourceMetadata":{"Data":{"Github":{"link":"https://github.com/x/test_keys/blob/abc/new_key#L2","repository":"https://github.com/x/test_keys.git","commit":"abc","file":"new_key","line":2}}},"SourceID":1,"SourceType":7,"SourceName":"trufflehog - github","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS cloud","DecoderName":"PLAIN","Verified":true,"VerificationFromCache":false,"Raw":"AKIAQYLPMN5HHHFPZAM2","RawV2":"AKIAQYLPMN5HHHFPZAM2:secret","Redacted":"AKIAQYLPMN5HHHFPZAM2","ExtraData":{"account":"052310077262","is_canary":"true"}}`)

	findings, err := parse(raw)
	if err != nil {
		t.Fatalf("parse() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Tool != "trufflehog" {
		t.Errorf("Tool = %q, want trufflehog", f.Tool)
	}
	if string(f.Severity) != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL (Verified=true)", f.Severity)
	}
	if f.RuleID != "AWS" {
		t.Errorf("RuleID = %q, want AWS", f.RuleID)
	}
	if f.CWE != "CWE-798" {
		t.Errorf("CWE = %q, want CWE-798", f.CWE)
	}
	if f.Path != "new_key" {
		t.Errorf("Path = %q, want new_key", f.Path)
	}
	if f.Line != 2 {
		t.Errorf("Line = %d, want 2", f.Line)
	}
}

// TestParse_UnverifiedIsHigh — unverified findings are still reportable but
// at HIGH severity (could be dead credential, rotated, or false positive).
func TestParse_UnverifiedIsHigh(t *testing.T) {
	raw := []byte(`{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/foo","line":10}}},"DetectorName":"GitHub","Verified":false,"Redacted":"ghp_xxx","Raw":"ghp_fullsecret"}`)
	findings, err := parse(raw)
	if err != nil {
		t.Fatalf("parse() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if string(findings[0].Severity) != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", findings[0].Severity)
	}
	if findings[0].Path != "/tmp/foo" {
		t.Errorf("Path = %q, want /tmp/foo (filesystem source)", findings[0].Path)
	}
}

// TestParse_SkipsLogLines — trufflehog mixes info logs and findings on stdout.
// Only lines with SourceMetadata should be processed.
func TestParse_SkipsLogLines(t *testing.T) {
	raw := []byte(`{"level":"info","msg":"running source","ts":"2026-04-22T10:00:00Z"}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"a.txt","line":1}}},"DetectorName":"Slack","Verified":false,"Redacted":"xoxb-1234"}
{"level":"info","msg":"finished scanning","chunks":27,"unverified_secrets":1}`)
	findings, err := parse(raw)
	if err != nil {
		t.Fatalf("parse() error = %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1 (log lines should be skipped)", len(findings))
	}
}

// TestParse_SkipsEmptyRedacted — findings without Redacted are false positives
// (e.g. URI detector matching /http:\/\/.*/).
func TestParse_SkipsEmptyRedacted(t *testing.T) {
	raw := []byte(`{"SourceMetadata":{"Data":{"Filesystem":{"file":"x","line":1}}},"DetectorName":"URI","Verified":false,"Redacted":"","Raw":""}`)
	findings, _ := parse(raw)
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (empty Redacted filtered)", len(findings))
	}
}

// TestParse_TruncatesRaw — raw secret should never be persisted in full.
func TestParse_TruncatesRaw(t *testing.T) {
	longSecret := "AKIAQYLPMN5HHHFPZAM2EXTRACHARSTHATSHOULDBECUT"
	raw := []byte(`{"SourceMetadata":{"Data":{"Filesystem":{"file":"x","line":1}}},"DetectorName":"AWS","Verified":false,"Redacted":"AKIA...","Raw":"` + longSecret + `"}`)
	findings, _ := parse(raw)
	if len(findings) != 1 {
		t.Fatal("parse failed")
	}
	preview, ok := findings[0].Raw["raw_preview"].(string)
	if !ok {
		t.Fatal("raw_preview not found in Raw map")
	}
	if len(preview) > 30 {
		t.Errorf("raw_preview len = %d, want <= 30 (truncation failed)", len(preview))
	}
	if preview == longSecret {
		t.Error("full secret persisted — security violation")
	}
}

func TestParse_MalformedLineSkipped(t *testing.T) {
	raw := []byte(`{"SourceMetadata":"not an object","DetectorName":"X"}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"a","line":1}}},"DetectorName":"AWS","Verified":false,"Redacted":"key"}`)
	findings, err := parse(raw)
	if err != nil {
		t.Fatalf("parse() should tolerate malformed line, got: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1 (1 malformed skipped)", len(findings))
	}
}
