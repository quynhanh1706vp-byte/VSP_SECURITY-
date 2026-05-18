package poam

import (
	"testing"
)

func TestMapCWEToControl_Known(t *testing.T) {
	cases := map[string]string{
		"CWE-79":  "SI-10",
		"CWE-89":  "SI-10",
		"CWE-22":  "AC-3",
		"CWE-798": "IA-5",
		"CWE-352": "SC-8",
		"CWE-327": "SC-13",
		"CWE-918": "SC-7",
		"CWE-119": "SI-16",
	}
	for cwe, expected := range cases {
		got := MapCWEToControl(cwe)
		if got != expected {
			t.Errorf("MapCWEToControl(%q) = %q, want %q", cwe, got, expected)
		}
	}
}

func TestMapCWEToControl_Unknown(t *testing.T) {
	got := MapCWEToControl("CWE-99999")
	if got != "SI-2" {
		t.Errorf("unknown CWE: got %q, want SI-2", got)
	}
}

func TestMapCWEToControl_Empty(t *testing.T) {
	got := MapCWEToControl("")
	if got != "SI-2" {
		t.Errorf("empty CWE: got %q, want SI-2", got)
	}
}

func TestMappingCount(t *testing.T) {
	n := MappingCount()
	if n < 50 {
		t.Errorf("expected ≥50 mappings, got %d", n)
	}
}

func TestNew_NilDB(t *testing.T) {
	w := New(nil, 0)
	if w == nil {
		t.Fatal("New returned nil")
	}
	if w.interval == 0 {
		t.Error("default interval not set")
	}
}
