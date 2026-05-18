package soar

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestScriptExecutor_Basic(t *testing.T) {
	exec := NewScriptExecutor(nil)
	n := &Node{
		ID: "n1", Type: StepScript,
		Config: json.RawMessage(`{"code":"return ctx.x * 2;"}`),
	}
	ec := &ExecCtx{Vars: map[string]interface{}{"x": 21}}
	out, _, err := exec.Run(context.Background(), n, ec)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal(out, &data)
	if data["value"].(float64) != 42 {
		t.Errorf("value = %v", data["value"])
	}
}

func TestScriptExecutor_NoCode(t *testing.T) {
	exec := NewScriptExecutor(nil)
	n := &Node{ID: "n1", Type: StepScript, Config: json.RawMessage(`{}`)}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestScriptExecutor_Timeout(t *testing.T) {
	exec := NewScriptExecutor(nil)
	n := &Node{
		ID: "n1", Type: StepScript,
		Config: json.RawMessage(`{"code":"while(true){}","timeout_seconds":1}`),
	}
	start := time.Now()
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("timeout not enforced: ran %v", time.Since(start))
	}
}

// stubApprover for approval executor tests
type stubApprover struct {
	id      string
	dec     string
	decided bool
}

func (s *stubApprover) CreateApproval(ctx context.Context, runID string, req *ApprovalRequest) (string, error) {
	if s.id == "" {
		s.id = "approval-1"
	}
	return s.id, nil
}

func (s *stubApprover) PollDecision(ctx context.Context, id string) (string, bool, error) {
	return s.dec, s.decided, nil
}

func TestApprovalExecutor_TestModeAutoApproves(t *testing.T) {
	exec := NewApprovalExecutor(nil)
	n := &Node{
		ID: "n1", Type: StepApproval,
		Config: json.RawMessage(`{"approvers":["alice@x.com"]}`),
	}
	out, _, err := exec.Run(context.Background(), n, &ExecCtx{IsTest: true})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal(out, &data)
	if data["decision"] != "approved" {
		t.Errorf("test mode should auto-approve: %v", data)
	}
}

func TestApprovalExecutor_RealModeReturnsPending(t *testing.T) {
	stub := &stubApprover{}
	exec := NewApprovalExecutor(stub)
	n := &Node{
		ID: "n1", Type: StepApproval,
		Config: json.RawMessage(`{"approvers":["a@x.com"],"timeout_minutes":30}`),
	}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{RunID: "run-1"})
	if !errors.Is(err, ErrApprovalPending) {
		t.Fatalf("expected ErrApprovalPending, got %v", err)
	}
}

func TestApprovalExecutor_NoApproversFails(t *testing.T) {
	exec := NewApprovalExecutor(&stubApprover{})
	n := &Node{
		ID: "n1", Type: StepApproval,
		Config: json.RawMessage(`{"approvers":[]}`),
	}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// stubSubRunner
type stubSubRunner struct {
	calledID string
	output   json.RawMessage
}

func (s *stubSubRunner) RunSub(ctx context.Context, parent *ExecCtx, pbID string, ovr map[string]interface{}) (json.RawMessage, error) {
	s.calledID = pbID
	if s.output == nil {
		s.output = json.RawMessage(`{"sub":"done"}`)
	}
	return s.output, nil
}

func TestSubPlaybookExecutor_Invokes(t *testing.T) {
	stub := &stubSubRunner{}
	exec := NewSubPlaybookExecutor(stub)
	n := &Node{
		ID: "n1", Type: StepSubPlaybook,
		Config: json.RawMessage(`{"playbook_id":"target-pb"}`),
	}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{Depth: 0})
	if err != nil {
		t.Fatal(err)
	}
	if stub.calledID != "target-pb" {
		t.Errorf("calledID = %q", stub.calledID)
	}
}

func TestSubPlaybookExecutor_DepthLimit(t *testing.T) {
	exec := NewSubPlaybookExecutor(&stubSubRunner{})
	n := &Node{
		ID: "n1", Type: StepSubPlaybook,
		Config: json.RawMessage(`{"playbook_id":"x"}`),
	}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{Depth: MaxRecursionDepth})
	if err == nil {
		t.Fatal("expected depth error")
	}
}

func TestForkExecutor_Plan(t *testing.T) {
	exec := &forkExecutor{}
	n := &Node{
		ID: "n_fork", Type: StepFork,
		Config: json.RawMessage(`{"branches":["a","b","c"],"join_node":"j","max_parallel":2}`),
	}
	out, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal(out, &data)
	if data["join_node"] != "j" {
		t.Errorf("join = %v", data["join_node"])
	}
	if data["max_parallel"].(float64) != 2 {
		t.Errorf("max_parallel = %v", data["max_parallel"])
	}
}

func TestForkExecutor_NodeLevelBranches(t *testing.T) {
	exec := &forkExecutor{}
	// Use Node.Branches / Node.JoinNode instead of Config
	n := &Node{
		ID:       "n_fork",
		Type:     StepFork,
		Branches: []string{"a", "b"},
		JoinNode: "j",
	}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestForkExecutor_NoBranchesFails(t *testing.T) {
	exec := &forkExecutor{}
	n := &Node{ID: "n", Type: StepFork, JoinNode: "j"}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestJoinExecutor(t *testing.T) {
	exec := &joinExecutor{}
	out, _, err := exec.Run(context.Background(), &Node{ID: "j", Type: StepJoin}, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal(out, &data)
	if data["_marker"] != "join" {
		t.Errorf("got %v", data)
	}
}

func TestRegisterIOExecutors(t *testing.T) {
	d := NewDispatcher()
	RegisterIOExecutors(d, &stubHTTPDoer{}, &stubNotifier{}, &stubTicketer{})
	for _, st := range []StepType{StepHTTP, StepNotify, StepTicket} {
		if !d.Has(st) {
			t.Errorf("not registered: %s", st)
		}
	}
}

func TestRegisterFlowExecutors(t *testing.T) {
	d := NewDispatcher()
	RegisterFlowExecutors(d, NewSandbox(), &stubApprover{}, &stubSubRunner{})
	for _, st := range []StepType{StepScript, StepApproval, StepSubPlaybook, StepFork, StepJoin} {
		if !d.Has(st) {
			t.Errorf("not registered: %s", st)
		}
	}
}
