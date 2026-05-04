// =====================================================================
// H3.T+W Tests
// Files split logically — but kept in ONE _test.go for ease of install.
// Place at: internal/agentic/agentic_test.go
//          (telemetry tests share package because both are internal/)
// =====================================================================

package agentic

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =====================================================================
// Sandbox / path-jail tests — the most security-critical surface
// =====================================================================

func TestSafePath_RejectsTraversal(t *testing.T) {
	bad := []string{
		"../etc/passwd",
		"foo/../../etc",
		"/etc/passwd",     // absolute
		"foo\x00bar",      // null byte
		"foo;rm -rf /",    // shell metacharacters
		"foo bar",         // space
		"",                // empty
		"foo$(whoami)",    // command substitution
		"foo|cat",         // pipe
	}
	for _, p := range bad {
		if safePath(p) {
			t.Errorf("safePath(%q) returned true — should reject", p)
		}
	}
}

func TestSafePath_AcceptsLegitimate(t *testing.T) {
	good := []string{
		"main.go",
		"internal/agentic/tools.go",
		"a/b/c/d.txt",
		"a-b_c.go",
		"file.tar.gz",
	}
	for _, p := range good {
		if !safePath(p) {
			t.Errorf("safePath(%q) returned false — should accept", p)
		}
	}
}

func TestResolveJailed_StaysInRoot(t *testing.T) {
	root := t.TempDir()
	// Legitimate sub-path
	abs, err := resolveJailed(root, "a/b.txt")
	if err != nil {
		t.Fatalf("legitimate path rejected: %v", err)
	}
	if !strings.HasPrefix(abs, root) {
		t.Errorf("resolved path %q escapes root %q", abs, root)
	}
}

func TestResolveJailed_BlocksEscape(t *testing.T) {
	root := t.TempDir()
	// Even though safePath catches "..", defense in depth: resolveJailed
	// also detects symlink-style escapes via filepath.Abs comparison.
	// Construct an attack: a relative path that when joined goes outside.
	// (safePath WOULD reject this, but we test the jail layer in isolation.)
	bad := strings.Repeat("../", 20) + "etc/passwd"
	if _, err := resolveJailed(root, bad); err == nil {
		t.Error("resolveJailed accepted traversal — jail broken")
	}
}

// =====================================================================
// ReadFileTool — happy + sad paths
// =====================================================================

func TestReadFileTool_Basic(t *testing.T) {
	root := t.TempDir()
	want := "alpha\nbeta\ngamma\ndelta\nepsilon\n"
	if err := os.WriteFile(filepath.Join(root, "x.txt"), []byte(want), 0644); err != nil {
		t.Fatal(err)
	}
	tool := &ReadFileTool{RepoRoot: root}
	res := tool.Run(context.Background(), map[string]any{
		"path": "x.txt", "start": 2, "end": 4,
	})
	if res.Error != "" {
		t.Fatalf("error: %s", res.Error)
	}
	if res.Output != "beta\ngamma\ndelta" {
		t.Errorf("got %q", res.Output)
	}
}

func TestReadFileTool_RejectsTraversal(t *testing.T) {
	root := t.TempDir()
	tool := &ReadFileTool{RepoRoot: root}
	res := tool.Run(context.Background(), map[string]any{
		"path": "../../etc/passwd",
	})
	if res.Error == "" {
		t.Fatal("expected error rejecting traversal")
	}
}

func TestReadFileTool_TruncatesLargeOutput(t *testing.T) {
	root := t.TempDir()
	// Write 6KB single line
	huge := strings.Repeat("A", 6000)
	if err := os.WriteFile(filepath.Join(root, "big.txt"), []byte(huge), 0644); err != nil {
		t.Fatal(err)
	}
	tool := &ReadFileTool{RepoRoot: root}
	res := tool.Run(context.Background(), map[string]any{"path": "big.txt"})
	if !res.Truncated {
		t.Error("expected Truncated=true for >4KB output")
	}
	if len(res.Output) > maxOutputBytes+50 {
		t.Errorf("output not capped at %dB: %d", maxOutputBytes, len(res.Output))
	}
}

// =====================================================================
// CheckImportsTool — go.mod parsing
// =====================================================================

func TestCheckImportsTool_Found(t *testing.T) {
	root := t.TempDir()
	gomod := `module example.com/x
go 1.22
require (
    github.com/google/uuid v1.6.0
    golang.org/x/crypto v0.31.0
)
`
	os.WriteFile(filepath.Join(root, "go.mod"), []byte(gomod), 0644)
	tool := &CheckImportsTool{RepoRoot: root}
	res := tool.Run(context.Background(), map[string]any{
		"import_path": "github.com/google/uuid",
	})
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	var parsed map[string]any
	json.Unmarshal([]byte(res.Output), &parsed)
	if parsed["present"] != true {
		t.Errorf("expected present=true, got %v", parsed)
	}
	if parsed["version"] != "v1.6.0" {
		t.Errorf("expected v1.6.0, got %v", parsed["version"])
	}
}

func TestCheckImportsTool_NotFound(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\ngo 1.22\n"), 0644)
	tool := &CheckImportsTool{RepoRoot: root}
	res := tool.Run(context.Background(), map[string]any{
		"import_path": "github.com/missing/pkg",
	})
	var parsed map[string]any
	json.Unmarshal([]byte(res.Output), &parsed)
	if parsed["present"] != false {
		t.Errorf("expected present=false")
	}
}

func TestCheckImportsTool_RejectsInjection(t *testing.T) {
	root := t.TempDir()
	tool := &CheckImportsTool{RepoRoot: root}
	bad := []string{
		"github.com/foo`whoami`",
		"github.com/foo bar",
		"github.com/foo'OR'1=1",
		"github.com/foo\nrm -rf",
	}
	for _, b := range bad {
		res := tool.Run(context.Background(), map[string]any{"import_path": b})
		if res.Error == "" {
			t.Errorf("CheckImports accepted suspicious input: %q", b)
		}
	}
}

// =====================================================================
// Tool timeout enforcement
// =====================================================================

func TestToolBox_RunRespectsTimeout(t *testing.T) {
	root := t.TempDir()
	tb := NewToolBox(root)
	// Use a known tool with valid input — verify it doesn't hang
	deadline := time.Now().Add(15 * time.Second)
	done := make(chan struct{})
	go func() {
		tb.Run(context.Background(), "list_files", map[string]any{"path": "."})
		close(done)
	}()
	select {
	case <-done:
		// ok
	case <-time.After(time.Until(deadline)):
		t.Fatal("tool did not return within 15s — timeout broken")
	}
}

func TestToolBox_RejectsUnknownTool(t *testing.T) {
	tb := NewToolBox(t.TempDir())
	res := tb.Run(context.Background(), "rm_rf", map[string]any{})
	if res.Error == "" || !strings.Contains(res.Error, "unknown tool") {
		t.Errorf("expected unknown tool error, got %v", res)
	}
}

// =====================================================================
// LLM reply parsing
// =====================================================================

func TestParseLLMReply_FinalAnswer(t *testing.T) {
	in := `{"thought":"I have it","final_answer":"Fix go.mod line 14"}`
	got := parseLLMReply(in)
	if got.FinalAnswer != "Fix go.mod line 14" {
		t.Errorf("got final=%q", got.FinalAnswer)
	}
}

func TestParseLLMReply_ToolCall(t *testing.T) {
	in := `{"thought":"need to read","tool":"read_file","input":{"path":"main.go","start":1,"end":50}}`
	got := parseLLMReply(in)
	if got.ToolName != "read_file" {
		t.Errorf("got tool=%q", got.ToolName)
	}
	if got.ToolInput["path"] != "main.go" {
		t.Errorf("input path missing: %v", got.ToolInput)
	}
}

func TestParseLLMReply_StripsCodeFence(t *testing.T) {
	in := "```json\n{\"final_answer\":\"hi\"}\n```"
	got := parseLLMReply(in)
	if got.FinalAnswer != "hi" {
		t.Errorf("code fence not stripped: %q", got.FinalAnswer)
	}
}

func TestParseLLMReply_HandlesPreamble(t *testing.T) {
	in := `Sure, here is my answer: {"thought":"x","final_answer":"y"} hope this helps`
	got := parseLLMReply(in)
	if got.FinalAnswer != "y" {
		t.Errorf("did not extract JSON from prose: %q", got.FinalAnswer)
	}
}

func TestParseLLMReply_BadJSON(t *testing.T) {
	in := `not even close to json`
	got := parseLLMReply(in)
	if got.FinalAnswer != "" || got.ToolName != "" {
		t.Errorf("bad JSON should yield empty intent: %+v", got)
	}
}

// =====================================================================
// HTTP handler smoke tests
// =====================================================================

func TestLooksLikeUUID(t *testing.T) {
	good := []string{
		"7ec29654-6ff7-4543-8810-30b346af5200",
		"00000000-0000-0000-0000-000000000000",
	}
	bad := []string{
		"not-a-uuid",
		"7ec296546ff745438810-30b346af5200",                // missing dashes
		"7ec29654-6ff7-4543-8810-30b346af520",              // 35 chars
		"7ec29654-6ff7-4543-8810-30b346af52000",            // 37 chars
		"GGGGGGGG-6ff7-4543-8810-30b346af5200",             // non-hex
		"7ec29654 6ff7 4543 8810 30b346af5200",             // spaces
	}
	for _, s := range good {
		if !looksLikeUUID(s) {
			t.Errorf("rejected legitimate UUID %q", s)
		}
	}
	for _, s := range bad {
		if looksLikeUUID(s) {
			t.Errorf("accepted bogus UUID %q", s)
		}
	}
}

func TestParseIntDef(t *testing.T) {
	cases := []struct {
		in   string
		def  int
		want int
	}{
		{"50", 10, 50},
		{"abc", 10, 10},
		{"", 10, 10},
		{"-5", 10, 10},
		{"99999999999999999999", 10, 10},
	}
	for _, c := range cases {
		got, _ := parseIntDef(c.in, c.def)
		if got != c.want {
			t.Errorf("parseIntDef(%q,%d)=%d want %d", c.in, c.def, got, c.want)
		}
	}
}

// =====================================================================
// Truncation helper
// =====================================================================

func TestTruncate(t *testing.T) {
	got, trunc := truncate("hello", 100)
	if got != "hello" || trunc {
		t.Errorf("short string mangled: %q trunc=%v", got, trunc)
	}
	long := strings.Repeat("x", 5000)
	got, trunc = truncate(long, 100)
	if !trunc {
		t.Error("expected trunc=true for long string")
	}
	if !strings.HasSuffix(got, "[TRUNCATED]") {
		t.Errorf("missing truncation marker: %q", got[len(got)-30:])
	}
}
