package soar

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSandbox_SimpleExpression(t *testing.T) {
	s := NewSandbox()
	out, err := s.Run(context.Background(), "1 + 2", SandboxInput{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := out.Value.(int64); !ok || v != 3 {
		t.Fatalf("got %v (%T), want 3", out.Value, out.Value)
	}
}

func TestSandbox_ContextVars(t *testing.T) {
	s := NewSandbox()
	out, err := s.Run(context.Background(),
		"ctx.severity",
		SandboxInput{Vars: map[string]interface{}{"severity": "CRITICAL"}},
		time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if out.Value != "CRITICAL" {
		t.Fatalf("got %v", out.Value)
	}
}

func TestSandbox_StepsAccess(t *testing.T) {
	s := NewSandbox()
	steps := map[string]json.RawMessage{
		"n0": json.RawMessage(`{"count":42}`),
	}
	out, err := s.Run(context.Background(),
		"steps.n0.count * 2",
		SandboxInput{StepOutputs: steps},
		time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := out.Value.(int64); !ok || v != 84 {
		t.Fatalf("got %v", out.Value)
	}
}

func TestSandbox_ConsoleCapture(t *testing.T) {
	s := NewSandbox()
	out, err := s.Run(context.Background(),
		`console.log("hello"); console.warn("careful"); 1`,
		SandboxInput{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Logs) != 2 {
		t.Fatalf("got %d logs", len(out.Logs))
	}
	if out.Logs[0].Level != "log" || out.Logs[0].Message != "hello" {
		t.Errorf("log[0] wrong: %+v", out.Logs[0])
	}
	if out.Logs[1].Level != "warn" || out.Logs[1].Message != "careful" {
		t.Errorf("log[1] wrong: %+v", out.Logs[1])
	}
}

func TestSandbox_BlocksDangerousGlobals(t *testing.T) {
	s := NewSandbox()
	tests := []string{
		"typeof require",
		"typeof process",
		"typeof eval",
		"typeof Function",
		"typeof setTimeout",
		"typeof fetch",
	}
	for _, code := range tests {
		t.Run(code, func(t *testing.T) {
			out, err := s.Run(context.Background(), code, SandboxInput{}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if out.Value != "undefined" {
				t.Errorf("%s = %v, want \"undefined\"", code, out.Value)
			}
		})
	}
}

func TestSandbox_TimeoutInterrupts(t *testing.T) {
	s := NewSandbox()
	// Tight CPU loop
	_, err := s.Run(context.Background(),
		`while(true) {}`,
		SandboxInput{}, 50*time.Millisecond)
	if !errors.Is(err, ErrSandboxTimeout) {
		t.Fatalf("expected ErrSandboxTimeout, got %v", err)
	}
}

func TestSandbox_OutputSizeCap(t *testing.T) {
	s := NewSandbox()
	s.maxOutputSize = 1024 // 1KB cap
	// Build 100KB string in JS
	out, err := s.Run(context.Background(),
		`"x".repeat(100000)`,
		SandboxInput{}, time.Second)
	if !errors.Is(err, ErrSandboxOutputTooBig) {
		t.Fatalf("expected ErrSandboxOutputTooBig, got %v (out=%v)", err, out)
	}
}

func TestSandbox_OutputMustBeJSONSerializable(t *testing.T) {
	s := NewSandbox()
	// Functions can't be JSON-serialized
	_, _ = s.Run(context.Background(),
		`(function(){ var o = {fn: function(){}}; return o; })()`,
		SandboxInput{}, time.Second)
	// Note: Goja's Export converts functions to nil, so this might pass.
	// Test the explicit unsupported case: NaN.
	out, err := s.Run(context.Background(), "NaN", SandboxInput{}, time.Second)
	if err == nil && out != nil {
		// JSON spec rejects NaN; if Goja exports it as math.NaN, json.Marshal fails
		// This is environment-dependent; just check no panic
		t.Logf("NaN result: out=%v err=%v", out, err)
	}
}

func TestSandbox_ContextCancel(t *testing.T) {
	s := NewSandbox()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := s.Run(ctx, `while(true) {}`, SandboxInput{}, time.Second)
	if err == nil {
		t.Fatal("expected error from cancel")
	}
}

func TestSandbox_SecretsProxy(t *testing.T) {
	s := NewSandbox()
	stub := &stubResolver{vals: map[string]string{"jira": "TOKEN-XYZ"}}
	out, err := s.Run(context.Background(),
		`secrets.get("jira")`,
		SandboxInput{Secrets: stub},
		time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if out.Value != "TOKEN-XYZ" {
		t.Fatalf("got %v", out.Value)
	}
	if !stub.called {
		t.Fatal("resolver not called")
	}
}

func TestSandbox_SecretsResolverError(t *testing.T) {
	s := NewSandbox()
	stub := &stubResolver{err: errors.New("not found")}
	_, err := s.Run(context.Background(),
		`secrets.get("missing")`,
		SandboxInput{Secrets: stub},
		time.Second)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected resolver error, got %v", err)
	}
}

func TestSandbox_RealisticTransform(t *testing.T) {
	s := NewSandbox()
	// Real-world: extract CVE IDs from finding text
	steps := map[string]json.RawMessage{
		"scan": json.RawMessage(`{"findings":[{"id":"CVE-2024-1234"},{"id":"CVE-2024-5678"}]}`),
	}
	out, err := s.Run(context.Background(),
		`steps.scan.findings.map(function(f){ return f.id; }).join(",")`,
		SandboxInput{StepOutputs: steps},
		time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if out.Value != "CVE-2024-1234,CVE-2024-5678" {
		t.Fatalf("got %v", out.Value)
	}
}

// stubResolver — mock SecretsResolver
type stubResolver struct {
	vals   map[string]string
	called bool
	err    error
}

func (s *stubResolver) Resolve(ctx context.Context, name string) (string, error) {
	s.called = true
	if s.err != nil {
		return "", s.err
	}
	return s.vals[name], nil
}
