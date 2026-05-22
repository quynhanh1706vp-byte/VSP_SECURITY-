package soar

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestSetVar_LiteralValue(t *testing.T) {
	exec := &setVarExecutor{}
	ec := &ExecCtx{Vars: map[string]interface{}{}}
	n := &Node{ID: "n1", Type: StepSetVar, Config: json.RawMessage(`{"name":"foo","value":"bar"}`)}
	out, next, err := exec.Run(context.Background(), n, ec)
	if err != nil {
		t.Fatal(err)
	}
	if next != "" {
		t.Errorf("unexpected next: %q", next)
	}
	if ec.Vars["foo"] != "bar" {
		t.Errorf("vars[foo] = %v", ec.Vars["foo"])
	}
	if !json.Valid(out) {
		t.Error("output not valid JSON")
	}
}

func TestSetVar_FromPath(t *testing.T) {
	exec := &setVarExecutor{}
	ec := &ExecCtx{
		Vars: map[string]interface{}{"original": "hello"},
	}
	n := &Node{ID: "n1", Type: StepSetVar, Config: json.RawMessage(`{"name":"copy","value_from":"ctx.original"}`)}
	_, _, err := exec.Run(context.Background(), n, ec)
	if err != nil {
		t.Fatal(err)
	}
	if ec.Vars["copy"] != "hello" {
		t.Errorf("vars[copy] = %v", ec.Vars["copy"])
	}
}

func TestSetVar_MissingName(t *testing.T) {
	exec := &setVarExecutor{}
	n := &Node{ID: "n1", Type: StepSetVar, Config: json.RawMessage(`{"value":"x"}`)}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCondition_TrueRoute(t *testing.T) {
	exec := &conditionExecutor{}
	n := &Node{
		ID: "n1", Type: StepCondition,
		Config:    json.RawMessage(`{"expr":"ctx.severity === 'CRITICAL'"}`),
		NextTrue:  "n_critical",
		NextFalse: "n_low",
	}
	ec := &ExecCtx{Vars: map[string]interface{}{"severity": "CRITICAL"}}
	_, next, err := exec.Run(context.Background(), n, ec)
	if err != nil {
		t.Fatal(err)
	}
	if next != "n_critical" {
		t.Errorf("got next=%q want n_critical", next)
	}
}

func TestCondition_FalseRoute(t *testing.T) {
	exec := &conditionExecutor{}
	n := &Node{
		ID: "n1", Type: StepCondition,
		Config:    json.RawMessage(`{"expr":"ctx.severity === 'CRITICAL'"}`),
		NextTrue:  "n_critical",
		NextFalse: "n_low",
	}
	ec := &ExecCtx{Vars: map[string]interface{}{"severity": "LOW"}}
	_, next, err := exec.Run(context.Background(), n, ec)
	if err != nil {
		t.Fatal(err)
	}
	if next != "n_low" {
		t.Errorf("got next=%q want n_low", next)
	}
}

func TestWait_Seconds(t *testing.T) {
	exec := &waitExecutor{}
	n := &Node{ID: "n1", Type: StepWait, Config: json.RawMessage(`{"seconds":1}`)}
	start := time.Now()
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	dur := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if dur < 900*time.Millisecond || dur > 2*time.Second {
		t.Errorf("waited %v, expected ~1s", dur)
	}
}

func TestWait_TestModeSkipsActualWait(t *testing.T) {
	exec := &waitExecutor{}
	n := &Node{ID: "n1", Type: StepWait, Config: json.RawMessage(`{"seconds":10}`)}
	ec := &ExecCtx{IsTest: true}
	start := time.Now()
	_, _, err := exec.Run(context.Background(), n, ec)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Error("test mode should skip actual wait")
	}
}

func TestWait_ContextCancel(t *testing.T) {
	exec := &waitExecutor{}
	n := &Node{ID: "n1", Type: StepWait, Config: json.RawMessage(`{"seconds":10}`)}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, _, err := exec.Run(ctx, n, &ExecCtx{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestWait_TooLong(t *testing.T) {
	exec := &waitExecutor{}
	n := &Node{ID: "n1", Type: StepWait, Config: json.RawMessage(`{"seconds":99999}`)}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err == nil {
		t.Fatal("expected error for excessive duration")
	}
}

func TestLoop_BuildsPlan(t *testing.T) {
	exec := &loopExecutor{}
	ec := &ExecCtx{
		StepOutputs: map[string]json.RawMessage{
			"n0": json.RawMessage(`{"findings":[{"id":1},{"id":2},{"id":3}]}`),
		},
	}
	n := &Node{
		ID: "n1", Type: StepLoop,
		Config: json.RawMessage(`{"items":"steps.n0.findings","body":"n_proc","item_var":"f"}`),
	}
	out, _, err := exec.Run(context.Background(), n, ec)
	if err != nil {
		t.Fatal(err)
	}
	var plan LoopPlan
	if err := json.Unmarshal(out, &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 3 || plan.Body != "n_proc" || plan.ItemVar != "f" {
		t.Errorf("plan = %+v", plan)
	}
}

func TestLoop_RejectsTooMany(t *testing.T) {
	exec := &loopExecutor{}
	// Build oversized array via raw JSON
	items := make([]int, MaxLoopIterations+1)
	for i := range items {
		items[i] = i
	}
	raw, _ := json.Marshal(map[string]interface{}{"big": items})
	ec := &ExecCtx{StepOutputs: map[string]json.RawMessage{"n0": raw}}
	n := &Node{
		ID: "n1", Type: StepLoop,
		Config: json.RawMessage(`{"items":"steps.n0.big","body":"n_b"}`),
	}
	_, _, err := exec.Run(context.Background(), n, ec)
	if err == nil {
		t.Fatal("expected error for too many items")
	}
}

func TestEnd_ReturnsTimestamp(t *testing.T) {
	exec := &endExecutor{}
	out, _, err := exec.Run(context.Background(), &Node{ID: "n_end", Type: StepEnd}, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(out, &data); err != nil {
		t.Fatal(err)
	}
	if data["ended_at"] == nil {
		t.Error("missing ended_at")
	}
}

func TestResolvePath(t *testing.T) {
	ec := &ExecCtx{
		Vars: map[string]interface{}{
			"sev": "HIGH",
			"meta": map[string]interface{}{
				"source": "scanner",
			},
		},
		StepOutputs: map[string]json.RawMessage{
			"n0": json.RawMessage(`{"count":42,"items":[{"id":"a"}]}`),
		},
	}
	tests := []struct {
		path string
		want interface{}
	}{
		{"ctx.sev", "HIGH"},
		{"ctx.meta.source", "scanner"},
		{"steps.n0.count", float64(42)}, // JSON numbers come back as float64
		{"ctx.missing", nil},
		{"steps.ghost.x", nil},
	}
	for _, tt := range tests {
		got := resolvePath(ec, tt.path)
		if got != tt.want {
			t.Errorf("resolvePath(%q) = %v (%T), want %v", tt.path, got, got, tt.want)
		}
	}
}

func TestIsTruthy(t *testing.T) {
	tests := []struct {
		v    interface{}
		want bool
	}{
		{nil, false}, {true, true}, {false, false},
		{"hello", true}, {"", false}, {"0", false}, {"false", false},
		{1, true}, {0, false},
		{int64(5), true}, {int64(0), false},
		{1.5, true}, {0.0, false},
		{[]interface{}{1}, true}, {[]interface{}{}, false},
		{map[string]interface{}{"a": 1}, true}, {map[string]interface{}{}, false},
	}
	for _, tt := range tests {
		if got := isTruthy(tt.v); got != tt.want {
			t.Errorf("isTruthy(%v %T) = %v, want %v", tt.v, tt.v, got, tt.want)
		}
	}
}
