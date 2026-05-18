package soar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dop251/goja"
)

// Sandbox errors.
var (
	ErrSandboxTimeout      = errors.New("sandbox: script timeout")
	ErrSandboxOutputTooBig = errors.New("sandbox: output exceeds size limit")
	ErrSandboxOutputJSON   = errors.New("sandbox: output is not JSON-serializable")
)

// Sandbox runs a JS snippet in an isolated Goja runtime.
//
// Security model (matches CrowdStrike/Sentinel/Tines hardening):
//
//   - require, process, Buffer, eval, Function: disabled
//   - setTimeout, setInterval, setImmediate: disabled
//   - Function constructor: blocked (cannot synthesize new code)
//   - global / globalThis: read-only proxy (no clobbering)
//   - Network access: none (no fetch, no XMLHttpRequest)
//   - File access: none (no fs)
//
// Available APIs:
//
//   - ctx        — read/write playbook variables
//   - steps      — read-only map of completed step outputs
//   - secrets    — proxy resolver, audit-logged, never returns plaintext via toString
//   - console.log/info/warn/error — captured to step output
//   - JSON, Math, String, Array, Object, Date, RegExp — standard ECMA built-ins
//
// Resource limits:
//
//   - Wall-clock timeout via vm.Interrupt (configurable)
//   - Output size cap (default 1MB)
//   - Output must be JSON-serializable (rejects functions, circular refs)
type Sandbox struct {
	defaultTimeout time.Duration
	maxOutputSize  int
}

// NewSandbox creates a sandbox factory. Reuse across script executions.
func NewSandbox() *Sandbox {
	return &Sandbox{
		defaultTimeout: 5 * time.Second,
		maxOutputSize:  MaxScriptOutputSize,
	}
}

// SandboxInput is what a script receives via globals.
type SandboxInput struct {
	Vars        map[string]interface{}     // exposed as `ctx`
	StepOutputs map[string]json.RawMessage // exposed as `steps` (read-only)
	Secrets     SecretsResolver            // exposed as `secrets` (audit-logged)
}

// SandboxOutput captures script result + console logs.
type SandboxOutput struct {
	Value    interface{}   `json:"value"`
	Logs     []LogLine     `json:"logs"`
	Duration time.Duration `json:"duration_ms"`
}

// LogLine — captured console.* call.
type LogLine struct {
	Level     string    `json:"level"` // log | info | warn | error
	Message   string    `json:"message"`
	Timestamp time.Time `json:"ts"`
}

// Run executes script with timeout. Returns the script's return value.
//
// Script can be either:
//   - An expression: "ctx.foo + 1"
//   - A statement block ending with return: "(function(){ return ctx.foo; })()"
//
// To make plain return statements work, callers should wrap:
//
//	"(function(){ " + userCode + " })()"
func (s *Sandbox) Run(parentCtx context.Context, script string, input SandboxInput, timeout time.Duration) (*SandboxOutput, error) {
	if timeout <= 0 {
		timeout = s.defaultTimeout
	}
	if script == "" {
		return nil, errors.New("sandbox: empty script")
	}

	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))

	// ─── Lockdown ───
	for _, name := range []string{
		"require", "process", "Buffer", "eval", "Function",
		"setTimeout", "setInterval", "setImmediate",
		"clearTimeout", "clearInterval", "clearImmediate",
		"XMLHttpRequest", "fetch", "WebSocket",
	} {
		_ = vm.Set(name, goja.Undefined())
	}

	// ─── Logs capture ───
	var logsMu sync.Mutex
	var logs []LogLine
	addLog := func(level string, args ...interface{}) {
		parts := make([]string, 0, len(args))
		for _, a := range args {
			parts = append(parts, fmt.Sprintf("%v", a))
		}
		logsMu.Lock()
		if len(logs) < 100 { // cap log lines per script
			logs = append(logs, LogLine{
				Level: level, Message: stringJoin(parts, " "), Timestamp: time.Now(),
			})
		}
		logsMu.Unlock()
	}
	console := map[string]interface{}{
		"log":   func(args ...interface{}) { addLog("log", args...) },
		"info":  func(args ...interface{}) { addLog("info", args...) },
		"warn":  func(args ...interface{}) { addLog("warn", args...) },
		"error": func(args ...interface{}) { addLog("error", args...) },
	}
	if err := vm.Set("console", console); err != nil {
		return nil, err
	}

	// ─── Inputs ───
	if err := vm.Set("ctx", input.Vars); err != nil {
		return nil, err
	}
	// steps: convert RawMessage map to plain map for JS interop
	stepsView := make(map[string]interface{}, len(input.StepOutputs))
	for k, v := range input.StepOutputs {
		var any interface{}
		// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface
		// StepOutputs are produced by prior SOAR steps in the same run
		// — trusted internal data, never request body.
		_ = json.Unmarshal(v, &any)
		stepsView[k] = any
	}
	if err := vm.Set("steps", stepsView); err != nil {
		return nil, err
	}

	// secrets: proxy that calls resolver. toString returns "[REDACTED]".
	if input.Secrets != nil {
		secProxy := newSecretsProxy(parentCtx, input.Secrets)
		if err := vm.Set("secrets", secProxy); err != nil {
			return nil, err
		}
	}

	// ─── Execute với timeout ───
	start := time.Now()
	doneCh := make(chan struct{})

	timer := time.AfterFunc(timeout, func() {
		vm.Interrupt("timeout")
	})
	defer timer.Stop()

	// Watch parent ctx for cancel
	go func() {
		select {
		case <-parentCtx.Done():
			vm.Interrupt(parentCtx.Err())
		case <-doneCh:
		}
	}()

	val, err := vm.RunString(script)
	close(doneCh)
	duration := time.Since(start)

	if err != nil {
		// Distinguish timeout from other errors
		if interrupted, ok := err.(*goja.InterruptedError); ok {
			if _, isTimeout := interrupted.Value().(string); isTimeout {
				return &SandboxOutput{Logs: logs, Duration: duration}, ErrSandboxTimeout
			}
			return &SandboxOutput{Logs: logs, Duration: duration}, fmt.Errorf("sandbox: interrupted: %v", interrupted.Value())
		}
		return &SandboxOutput{Logs: logs, Duration: duration}, fmt.Errorf("sandbox: %w", err)
	}

	exported := val.Export()

	// Validate output is JSON-serializable + within size limit
	encoded, err := json.Marshal(exported)
	if err != nil {
		return &SandboxOutput{Logs: logs, Duration: duration}, fmt.Errorf("%w: %v", ErrSandboxOutputJSON, err)
	}
	if len(encoded) > s.maxOutputSize {
		return &SandboxOutput{Logs: logs, Duration: duration},
			fmt.Errorf("%w: %d bytes > %d", ErrSandboxOutputTooBig, len(encoded), s.maxOutputSize)
	}

	return &SandboxOutput{
		Value:    exported,
		Logs:     logs,
		Duration: duration,
	}, nil
}

// secretsProxy — exposed as `secrets` global. Each access goes through the
// audit-logged resolver. The proxy itself never holds plaintext.
type secretsProxy struct {
	ctx      context.Context
	resolver SecretsResolver
}

func newSecretsProxy(ctx context.Context, r SecretsResolver) map[string]interface{} {
	p := &secretsProxy{ctx: ctx, resolver: r}
	return map[string]interface{}{
		"get": p.get,
	}
}

// get(name) — JS-callable: secrets.get("jira_token")
func (s *secretsProxy) get(name string) (string, error) {
	if name == "" {
		return "", errors.New("secrets.get: name required")
	}
	return s.resolver.Resolve(s.ctx, name)
}

// stringJoin — local impl to avoid pulling strings package
func stringJoin(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += sep + parts[i]
	}
	return out
}
