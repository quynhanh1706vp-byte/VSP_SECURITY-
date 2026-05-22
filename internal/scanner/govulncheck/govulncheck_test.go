package govulncheck

import (
	"strings"
	"testing"
)

func TestName(t *testing.T) {
	a := New()
	if a.Name() != "govulncheck" {
		t.Errorf("expected name 'govulncheck', got %q", a.Name())
	}
}

func TestParseRealShape(t *testing.T) {
	// Newline-delimited JSON (govulncheck -format json output)
	input := []byte(`{"osv":{"id":"GO-2024-2887","aliases":["CVE-2024-24790"],"summary":"net/netip: Unexpected behavior from Is methods for IPv4-mapped IPv6 addresses","details":"long details..."}}
{"finding":{"osv":"GO-2024-2887","fixed_version":"go1.22.4","trace":[{"module":"std","version":"v0.0.0","package":"net/netip","function":"Addr.Is4In6"}]}}
{"osv":{"id":"GO-2024-9999","aliases":["CVE-2024-XXXXX"],"summary":"fake vuln for test"}}
{"finding":{"osv":"GO-2024-9999","fixed_version":"v1.2.3","trace":[{"module":"github.com/example/foo","version":"v1.0.0","package":"github.com/example/foo/bar"}]}}`)

	findings, err := parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// First finding
	f := findings[0]
	if f.Tool != "govulncheck" {
		t.Errorf("expected tool=govulncheck, got %q", f.Tool)
	}
	if f.Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.RuleID != "GO-2024-2887" {
		t.Errorf("expected rule GO-2024-2887, got %q", f.RuleID)
	}
	if f.CWE != "CVE-2024-24790" {
		t.Errorf("expected CVE-2024-24790 in CWE field, got %q", f.CWE)
	}
	if !strings.Contains(f.Message, "IPv4-mapped") {
		t.Errorf("expected summary in message, got %q", f.Message)
	}
	if f.FixSignal != "upgrade std to go1.22.4" {
		t.Errorf("unexpected fix signal: %q", f.FixSignal)
	}
}

func TestParseEmpty(t *testing.T) {
	findings, err := parse([]byte(``))
	if err == nil {
		// empty input: parser may error or return nil; accept both
		if len(findings) != 0 {
			t.Errorf("expected 0 findings on empty input, got %d", len(findings))
		}
	}
}

func TestParseOrphanFinding(t *testing.T) {
	// Finding with no matching OSV entry — should still produce a Finding
	// using OSV ID as fallback
	input := []byte(`{"finding":{"osv":"GO-ORPHAN","trace":[{"module":"m","package":"p"}]}}`)
	findings, err := parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CWE != "GO-ORPHAN" {
		t.Errorf("expected fallback to OSV id, got %q", findings[0].CWE)
	}
}
