package soar

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ─────────────────────────────────────────────────────────────────
// set_var — store value into ec.Vars
//
// Config: {"name":"foo","value":"bar"}            // literal value
//         {"name":"foo","value_from":"steps.n0.x"} // copy from previous step
// ─────────────────────────────────────────────────────────────────

type setVarExecutor struct{}

type setVarConfig struct {
	Name      string      `json:"name"`
	Value     interface{} `json:"value,omitempty"`
	ValueFrom string      `json:"value_from,omitempty"`
}

func (e *setVarExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg, err := parseConfig[setVarConfig](n)
	if err != nil {
		return nil, "", err
	}
	if cfg.Name == "" {
		return nil, "", fmt.Errorf("set_var: name required")
	}

	var value = cfg.Value
	if cfg.ValueFrom != "" {
		value = resolvePath(ec, cfg.ValueFrom)
	}

	if ec.Vars == nil {
		ec.Vars = make(map[string]interface{})
	}
	ec.Vars[cfg.Name] = value

	out, _ := json.Marshal(map[string]interface{}{
		"name":  cfg.Name,
		"value": value,
	})
	return out, "", nil
}

// ─────────────────────────────────────────────────────────────────
// condition — branch based on JS expression
//
// Config: {"expr":"ctx.severity === 'CRITICAL'"}
//
// Engine reads node.NextTrue / node.NextFalse to route. If expression
// evaluates truthy → next is NextTrue; falsy → NextFalse.
// ─────────────────────────────────────────────────────────────────

type conditionExecutor struct {
	sandbox *Sandbox // nil → uses default
}

// NewConditionExecutor allows injecting a shared sandbox.
func NewConditionExecutor(s *Sandbox) StepExecutor {
	return &conditionExecutor{sandbox: s}
}

type conditionConfig struct {
	Expr string `json:"expr"`
}

func (e *conditionExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg, err := parseConfig[conditionConfig](n)
	if err != nil {
		return nil, "", err
	}
	// Fall back to legacy YAML-string config_raw if no JSON expr provided
	if cfg.Expr == "" && n.ConfigRaw != "" {
		cfg.Expr = legacyConditionToJS(n.ConfigRaw)
	}
	if cfg.Expr == "" {
		return nil, "", fmt.Errorf("condition: expr required")
	}

	// Wrap expr to ensure it returns a value
	script := "(function(){ return (" + cfg.Expr + "); })()"

	sb := e.sandbox
	if sb == nil {
		sb = NewSandbox()
	}
	out, err := sb.Run(ctx, script, SandboxInput{
		Vars:        ec.Vars,
		StepOutputs: ec.StepOutputs,
		Secrets:     ec.Secrets,
	}, 5*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("condition expr: %w", err)
	}

	truthy := isTruthy(out.Value)
	next := n.NextFalse
	if truthy {
		next = n.NextTrue
	}

	result, _ := json.Marshal(map[string]interface{}{
		"expr":   cfg.Expr,
		"value":  out.Value,
		"truthy": truthy,
		"next":   next,
	})
	return result, next, nil
}

// ─────────────────────────────────────────────────────────────────
// wait — sleep for N seconds, or until timestamp
//
// Config: {"seconds":5}
//         {"until":"2026-05-04T18:00:00Z"}
// ─────────────────────────────────────────────────────────────────

type waitExecutor struct{}

type waitConfig struct {
	Seconds int    `json:"seconds,omitempty"`
	Until   string `json:"until,omitempty"`
}

func (e *waitExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg, err := parseConfig[waitConfig](n)
	if err != nil {
		return nil, "", err
	}

	var dur time.Duration
	switch {
	case cfg.Seconds > 0:
		if cfg.Seconds > MaxStepDurationSec {
			return nil, "", fmt.Errorf("wait: max %d seconds", MaxStepDurationSec)
		}
		dur = time.Duration(cfg.Seconds) * time.Second
	case cfg.Until != "":
		t, err := time.Parse(time.RFC3339, cfg.Until)
		if err != nil {
			return nil, "", fmt.Errorf("wait: invalid until time: %w", err)
		}
		dur = time.Until(t)
		if dur < 0 {
			dur = 0
		}
		if dur > time.Duration(MaxStepDurationSec)*time.Second {
			return nil, "", fmt.Errorf("wait: until exceeds %d seconds", MaxStepDurationSec)
		}
	default:
		return nil, "", fmt.Errorf("wait: need seconds or until")
	}

	if ec.IsTest {
		// In test mode, skip the actual wait
		out, _ := json.Marshal(map[string]interface{}{
			"waited_ms": 0,
			"test_mode": true,
		})
		return out, "", nil
	}

	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case <-time.After(dur):
	}

	out, _ := json.Marshal(map[string]interface{}{
		"waited_ms": dur.Milliseconds(),
	})
	return out, "", nil
}

// ─────────────────────────────────────────────────────────────────
// loop — iterate over array, execute body node per item
//
// Config: {"items":"steps.n0.findings","body":"n_body","item_var":"finding"}
//         "items" is dot-path into ec; "body" is target node ID;
//         "item_var" is name in ctx during body execution.
//
// Note: actual body execution is engine concern (loop step records the
// items + delegates to engine.executeLoop). This executor only validates
// and returns the iteration plan.
// ─────────────────────────────────────────────────────────────────

type loopExecutor struct{}

type loopConfig struct {
	Items   string `json:"items"`
	Body    string `json:"body"`
	ItemVar string `json:"item_var,omitempty"`
}

// LoopPlan is what the loop executor returns. Engine reads this and
// drives the per-item iteration.
type LoopPlan struct {
	Items   []interface{} `json:"items"`
	Body    string        `json:"body"`
	ItemVar string        `json:"item_var"`
}

func (e *loopExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg, err := parseConfig[loopConfig](n)
	if err != nil {
		return nil, "", err
	}
	if cfg.Items == "" || cfg.Body == "" {
		return nil, "", fmt.Errorf("loop: items and body required")
	}
	if cfg.ItemVar == "" {
		cfg.ItemVar = "item"
	}

	resolved := resolvePath(ec, cfg.Items)
	items, ok := toSlice(resolved)
	if !ok {
		return nil, "", fmt.Errorf("loop: items=%q resolved to non-array (%T)", cfg.Items, resolved)
	}
	if len(items) > MaxLoopIterations {
		return nil, "", fmt.Errorf("loop: %d items exceeds max %d", len(items), MaxLoopIterations)
	}

	plan := LoopPlan{
		Items:   items,
		Body:    cfg.Body,
		ItemVar: cfg.ItemVar,
	}
	out, err := json.Marshal(plan)
	return out, "", err
}

// ─────────────────────────────────────────────────────────────────
// end — terminator. Marks playbook as done. No outgoing edges expected.
// ─────────────────────────────────────────────────────────────────

type endExecutor struct{}

func (e *endExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	out, _ := json.Marshal(map[string]interface{}{
		"ended_at": time.Now().UTC().Format(time.RFC3339),
		"reason":   "playbook reached end node",
	})
	return out, "", nil
}

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────

// parseConfig unmarshals a node's Config field into the type-specific struct.
// Empty config returns zero value (caller validates required fields).
func parseConfig[T any](n *Node) (T, error) {
	var cfg T
	if len(n.Config) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(n.Config, &cfg); err != nil {
		return cfg, fmt.Errorf("%s config: %w", n.Type, err)
	}
	return cfg, nil
}

// resolvePath looks up a dot-path against ec.
//
// Supported roots:
//   - ctx.X.Y.Z      — into ec.Vars
//   - steps.NID.X.Y  — into ec.StepOutputs[NID]
//
// Returns nil for missing paths (callers handle).
func resolvePath(ec *ExecCtx, path string) interface{} {
	if path == "" {
		return nil
	}
	parts := splitDot(path)
	if len(parts) == 0 {
		return nil
	}

	var root interface{}
	switch parts[0] {
	case "ctx":
		root = mapToInterface(ec.Vars)
		parts = parts[1:]
	case "steps":
		if len(parts) < 2 {
			return nil
		}
		raw, ok := ec.StepOutputs[parts[1]]
		if !ok {
			return nil
		}
		var v interface{}
		_ = json.Unmarshal(raw, &v)
		root = v
		parts = parts[2:]
	default:
		// Treat as direct ctx key
		root = mapToInterface(ec.Vars)
	}

	cur := root
	for _, p := range parts {
		switch m := cur.(type) {
		case map[string]interface{}:
			cur = m[p]
		default:
			return nil
		}
	}
	return cur
}

func splitDot(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '.' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func mapToInterface(m map[string]interface{}) interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	return interface{}(m)
}

// isTruthy mimics JS truthiness for condition results.
func isTruthy(v interface{}) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != "" && x != "0" && x != "false"
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case []interface{}:
		return len(x) > 0
	case map[string]interface{}:
		return len(x) > 0
	}
	return true
}

func toSlice(v interface{}) ([]interface{}, bool) {
	if v == nil {
		return nil, false
	}
	if s, ok := v.([]interface{}); ok {
		return s, true
	}
	return nil, false
}
