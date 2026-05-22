package soar

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// Integration tests for engine — uses in-memory mock store.
// ════════════════════════════════════════════════════════════════════

// memEngineStore — in-memory mock of EngineStore
type memEngineStore struct {
	mu              sync.Mutex
	playbooks       map[string]*Playbook
	runs            map[string]map[string]interface{} // runID → {status, currentNode, results, error, finishedDur}
	approvals       map[string]string                 // approvalID → decision
	approvalDecided map[string]bool
}

func newMemStore() *memEngineStore {
	return &memEngineStore{
		playbooks:       make(map[string]*Playbook),
		runs:            make(map[string]map[string]interface{}),
		approvals:       make(map[string]string),
		approvalDecided: make(map[string]bool),
	}
}

func (m *memEngineStore) AddPlaybook(pb *Playbook) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.playbooks[pb.ID] = pb
}

func (m *memEngineStore) GetPlaybook(ctx context.Context, tenantID, id string) (*Playbook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pb, ok := m.playbooks[id]
	if !ok {
		return nil, &EngineError{Wrapped: errMockNotFound}
	}
	return pb, nil
}

func (m *memEngineStore) CreateRun(ctx context.Context, p CreateRunArgs) (string, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := "run-" + p.PlaybookID + "-" + time.Now().Format("150405.000000")
	m.runs[id] = map[string]interface{}{
		"status": "running",
	}
	return id, time.Now(), nil
}

func (m *memEngineStore) UpdateRunStatus(ctx context.Context, runID, status, currentNode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.runs[runID]; ok {
		r["status"] = status
		r["current_node"] = currentNode
	}
	return nil
}

func (m *memEngineStore) UpdateRunResults(ctx context.Context, runID string, stepResults json.RawMessage, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.runs[runID]; ok {
		r["step_results"] = stepResults
		r["error"] = errMsg
	}
	return nil
}

func (m *memEngineStore) FinishRun(ctx context.Context, runID, status string, durationMS int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.runs[runID]; ok {
		r["status"] = status
		r["duration_ms"] = durationMS
	}
	return nil
}

func (m *memEngineStore) CreateApproval(ctx context.Context, runID string, req *ApprovalRequest) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := "appr-" + runID
	m.approvals[id] = ""
	m.approvalDecided[id] = false
	return id, nil
}

func (m *memEngineStore) PollDecision(ctx context.Context, approvalID string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.approvals[approvalID], m.approvalDecided[approvalID], nil
}

var errMockNotFound = &mockErr{msg: "not found"}

type mockErr struct{ msg string }

func (e *mockErr) Error() string { return e.msg }

// captureBroadcaster — collects broadcast events for assertions
type captureBroadcaster struct {
	mu     sync.Mutex
	events []json.RawMessage
}

func (c *captureBroadcaster) Broadcast(msg []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dup := make([]byte, len(msg))
	copy(dup, msg)
	c.events = append(c.events, dup)
}

func (c *captureBroadcaster) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// ─── helper: build engine with default executors ───

func mkEngine(t *testing.T) (*Engine, *memEngineStore, *captureBroadcaster) {
	t.Helper()
	store := newMemStore()
	disp := NewDispatcher()
	disp.RegisterDefault()
	disp.Register(StepFork, &forkExecutor{})
	disp.Register(StepJoin, &joinExecutor{})
	disp.Register(StepScript, NewScriptExecutor(NewSandbox()))
	disp.Register(StepHTTP, NewHTTPExecutor(nil)) // test mode
	disp.Register(StepNotify, NewNotifyExecutor(nil))
	disp.Register(StepTicket, NewTicketExecutor(nil))
	disp.Register(StepApproval, NewApprovalExecutor(nil))
	disp.Register(StepSubPlaybook, NewSubPlaybookExecutor(nil))

	bc := &captureBroadcaster{}
	eng, err := New(EngineConfig{
		Store: store, Dispatcher: disp, Broadcaster: bc,
		StepTimeout: 5 * time.Second, RunTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return eng, store, bc
}

// ─── Tests ───

func TestEngine_LinearChain(t *testing.T) {
	eng, _, bc := mkEngine(t)
	pb := &Playbook{
		ID: "pb1", TenantID: "t1", Name: "linear", Status: "enabled",
		Graph: Graph{
			Nodes: []Node{
				{ID: "n0", Type: StepSetVar, Config: json.RawMessage(`{"name":"x","value":"hello"}`)},
				{ID: "n1", Type: StepSetVar, Config: json.RawMessage(`{"name":"y","value":"world"}`)},
				{ID: "n2", Type: StepEnd},
			},
			Edges: [][2]string{{"n0", "n1"}, {"n1", "n2"}},
			Entry: "n0",
		},
	}
	run, err := eng.Execute(context.Background(), pb, ExecuteOptions{IsTest: true})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != RunSuccess {
		t.Fatalf("status=%s, expected success: %s", run.Status, run.Error)
	}
	if len(run.StepResults) != 3 {
		t.Errorf("expected 3 step results, got %d", len(run.StepResults))
	}
	if bc.Count() < 4 { // run:start + 3 step:done + run:end
		t.Errorf("broadcasts=%d, expected >=4", bc.Count())
	}
}

func TestEngine_ConditionalBranch(t *testing.T) {
	eng, _, _ := mkEngine(t)
	pb := &Playbook{
		ID: "pb2", TenantID: "t1", Status: "enabled",
		Graph: Graph{
			Nodes: []Node{
				{ID: "n0", Type: StepCondition,
					Config:   json.RawMessage(`{"expr":"ctx.severity === 'CRITICAL'"}`),
					NextTrue: "n_critical", NextFalse: "n_low"},
				{ID: "n_critical", Type: StepSetVar, Config: json.RawMessage(`{"name":"action","value":"isolate"}`)},
				{ID: "n_low", Type: StepSetVar, Config: json.RawMessage(`{"name":"action","value":"log"}`)},
				{ID: "n_end", Type: StepEnd},
			},
			Edges: [][2]string{{"n_critical", "n_end"}, {"n_low", "n_end"}},
			Entry: "n0",
		},
	}
	// CRITICAL → should take n_critical branch
	run, err := eng.Execute(context.Background(), pb, ExecuteOptions{
		IsTest:  true,
		Context: map[string]interface{}{"severity": "CRITICAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != RunSuccess {
		t.Fatalf("status=%s err=%s", run.Status, run.Error)
	}
	// Verify n_critical ran (not n_low)
	hasCritical := false
	hasLow := false
	for _, sr := range run.StepResults {
		if sr.NodeID == "n_critical" {
			hasCritical = true
		}
		if sr.NodeID == "n_low" {
			hasLow = true
		}
	}
	if !hasCritical || hasLow {
		t.Errorf("wrong branch taken: critical=%v low=%v", hasCritical, hasLow)
	}
}

func TestEngine_Loop(t *testing.T) {
	eng, _, _ := mkEngine(t)

	// Simulate ctx with array via set_var
	pb := &Playbook{
		ID: "pb3", TenantID: "t1", Status: "enabled",
		Graph: Graph{
			Nodes: []Node{
				{ID: "n_init", Type: StepSetVar,
					Config: json.RawMessage(`{"name":"items","value":[1,2,3]}`)},
				{ID: "n_loop", Type: StepLoop,
					Config: json.RawMessage(`{"items":"ctx.items","body":"n_body","item_var":"x"}`)},
				{ID: "n_body", Type: StepSetVar,
					Config: json.RawMessage(`{"name":"last","value_from":"ctx.x"}`)},
				{ID: "n_end", Type: StepEnd},
			},
			Edges: [][2]string{{"n_init", "n_loop"}, {"n_loop", "n_body"}, {"n_loop", "n_end"}},
			Entry: "n_init",
		},
	}
	run, err := eng.Execute(context.Background(), pb, ExecuteOptions{IsTest: true})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != RunSuccess {
		t.Fatalf("status=%s err=%s", run.Status, run.Error)
	}
	// Should have: init + loop + 3x body + end = 6 results
	bodyCount := 0
	for _, sr := range run.StepResults {
		if sr.NodeID == "n_body[0]" || sr.NodeID == "n_body[1]" || sr.NodeID == "n_body[2]" {
			bodyCount++
		}
	}
	if bodyCount != 3 {
		t.Errorf("body iterations = %d, expected 3", bodyCount)
	}
}

func TestEngine_StepFailureAborts(t *testing.T) {
	eng, _, _ := mkEngine(t)
	pb := &Playbook{
		ID: "pb4", TenantID: "t1", Status: "enabled",
		Graph: Graph{
			Nodes: []Node{
				{ID: "n0", Type: StepSetVar, Config: json.RawMessage(`{}`)}, // missing 'name' → fails
				{ID: "n1", Type: StepEnd},
			},
			Edges: [][2]string{{"n0", "n1"}},
			Entry: "n0",
		},
	}
	run, _ := eng.Execute(context.Background(), pb, ExecuteOptions{IsTest: true})
	if run.Status != RunFailed {
		t.Fatalf("expected failed, got %s", run.Status)
	}
	if run.Error == "" {
		t.Error("expected error message")
	}
}

func TestEngine_OnFailureContinue(t *testing.T) {
	eng, _, _ := mkEngine(t)
	pb := &Playbook{
		ID: "pb5", TenantID: "t1", Status: "enabled",
		Graph: Graph{
			Nodes: []Node{
				{ID: "n0", Type: StepSetVar, Config: json.RawMessage(`{}`),
					OnFailure: OnFailContinue},
				{ID: "n1", Type: StepEnd},
			},
			Edges: [][2]string{{"n0", "n1"}},
			Entry: "n0",
		},
	}
	run, _ := eng.Execute(context.Background(), pb, ExecuteOptions{IsTest: true})
	if run.Status != RunSuccess {
		t.Fatalf("expected success with on_failure=continue, got %s err=%s", run.Status, run.Error)
	}
}

func TestEngine_TimeoutHonored(t *testing.T) {
	store := newMemStore()
	disp := NewDispatcher()
	disp.RegisterDefault()
	eng, _ := New(EngineConfig{
		Store: store, Dispatcher: disp,
		RunTimeout: 200 * time.Millisecond,
	})
	pb := &Playbook{
		ID: "pb6", TenantID: "t1", Status: "enabled",
		Graph: Graph{
			Nodes: []Node{
				{ID: "n0", Type: StepWait, Config: json.RawMessage(`{"seconds":10}`)},
				{ID: "n1", Type: StepEnd},
			},
			Edges: [][2]string{{"n0", "n1"}},
			Entry: "n0",
		},
	}
	run, _ := eng.Execute(context.Background(), pb, ExecuteOptions{IsTest: false})
	if run.Status != RunTimeout && run.Status != RunFailed {
		t.Fatalf("expected timeout/failed, got %s", run.Status)
	}
}

func TestEngine_LegacyPlaybookCompat(t *testing.T) {
	eng, _, _ := mkEngine(t)
	// Simulate the migrated "Gate FAIL auto-response" playbook structure.
	pb := &Playbook{
		ID: "pb-legacy", TenantID: "t1", Status: "enabled",
		Graph: Graph{
			Nodes: []Node{
				{ID: "n0", Type: StepCondition,
					ConfigRaw: "gate=FAIL AND severity IN [CRITICAL,HIGH]",
					NextTrue:  "n1", NextFalse: "n_end"},
				{ID: "n1", Type: StepEnrich,
					ConfigRaw: "source: NVD,OSV\nfields: [cvss,epss,kev]"},
				{ID: "n2", Type: StepBlock,
					ConfigRaw: "provider: github\nstatus: failure\ncontext: vsp/gate"},
				{ID: "n3", Type: StepTicket,
					ConfigRaw: "project: VSP-SECURITY\npriority: P1\nauto_assign: security-team"},
				{ID: "n4", Type: StepNotify,
					ConfigRaw: "channel: #security-alerts\nping: @security-oncall"},
				{ID: "n_end", Type: StepEnd},
			},
			Edges: [][2]string{
				{"n1", "n2"}, {"n2", "n3"}, {"n3", "n4"}, {"n4", "n_end"},
			},
			Entry: "n0",
		},
	}
	run, err := eng.Execute(context.Background(), pb, ExecuteOptions{
		IsTest: true,
		Context: map[string]interface{}{
			"gate":     "FAIL",
			"severity": "HIGH",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != RunSuccess {
		t.Fatalf("legacy playbook failed: status=%s err=%s", run.Status, run.Error)
	}
	// Should have executed: condition + 4 legacy steps + end = 6
	if len(run.StepResults) < 5 {
		t.Errorf("step results = %d, expected >= 5", len(run.StepResults))
	}
}

func TestManager_ExecuteByID(t *testing.T) {
	eng, store, _ := mkEngine(t)
	pb := &Playbook{
		ID: "managed", TenantID: "t1", Status: "enabled",
		Graph: Graph{
			Nodes: []Node{
				{ID: "n0", Type: StepEnd},
			},
			Entry: "n0",
		},
	}
	store.AddPlaybook(pb)

	mgr := NewManager(eng, store)
	run, err := mgr.ExecuteByID(context.Background(), "t1", "managed", ExecuteOptions{IsTest: true})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != RunSuccess {
		t.Errorf("status=%s", run.Status)
	}
}

func TestManager_RejectsDisabledPlaybook(t *testing.T) {
	eng, store, _ := mkEngine(t)
	pb := &Playbook{
		ID: "disabled-pb", TenantID: "t1", Status: "disabled",
		Graph: Graph{Nodes: []Node{{ID: "n0", Type: StepEnd}}, Entry: "n0"},
	}
	store.AddPlaybook(pb)
	mgr := NewManager(eng, store)
	_, err := mgr.ExecuteByID(context.Background(), "t1", "disabled-pb", ExecuteOptions{})
	if err == nil {
		t.Fatal("expected error for disabled playbook")
	}
}

func TestManager_AllowsTestModeOnDisabled(t *testing.T) {
	eng, store, _ := mkEngine(t)
	pb := &Playbook{
		ID: "test-disabled", TenantID: "t1", Status: "disabled",
		Graph: Graph{Nodes: []Node{{ID: "n0", Type: StepEnd}}, Entry: "n0"},
	}
	store.AddPlaybook(pb)
	mgr := NewManager(eng, store)
	run, err := mgr.ExecuteByID(context.Background(), "t1", "test-disabled", ExecuteOptions{IsTest: true})
	if err != nil {
		t.Fatalf("test mode should bypass disabled check: %v", err)
	}
	if run.Status != RunSuccess {
		t.Errorf("status=%s", run.Status)
	}
}
