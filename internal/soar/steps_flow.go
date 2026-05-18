package soar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ─────────────────────────────────────────────────────────────────
// script — run JS in Goja sandbox, return value
//
// Config: {"code":"return ctx.x * 2;","timeout_seconds":5}
//
// Note: code is wrapped in (function(){ ... })() so plain `return`
// statements work. Code that's just an expression (no return) also works.
// ─────────────────────────────────────────────────────────────────

type scriptExecutor struct {
	sandbox *Sandbox
}

// NewScriptExecutor — pass shared sandbox for memory efficiency.
func NewScriptExecutor(s *Sandbox) StepExecutor {
	return &scriptExecutor{sandbox: s}
}

type scriptConfig struct {
	Code           string `json:"code"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

func (e *scriptExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg, err := parseConfig[scriptConfig](n)
	if err != nil {
		return nil, "", err
	}
	if cfg.Code == "" {
		return nil, "", fmt.Errorf("script: code required")
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	sb := e.sandbox
	if sb == nil {
		sb = NewSandbox()
	}

	// Wrap code in IIFE so 'return' works
	wrapped := "(function(){ " + cfg.Code + " })()"

	out, err := sb.Run(ctx, wrapped, SandboxInput{
		Vars:        ec.Vars,
		StepOutputs: ec.StepOutputs,
		Secrets:     ec.Secrets,
	}, timeout)
	if err != nil {
		return nil, "", fmt.Errorf("script: %w", err)
	}

	result := map[string]interface{}{
		"value":       out.Value,
		"logs":        out.Logs,
		"duration_ms": out.Duration.Milliseconds(),
	}
	res, err := json.Marshal(result)
	return res, "", err
}

// ─────────────────────────────────────────────────────────────────
// approval — pause run, wait for human decision
//
// Config:
//   {
//     "approvers": ["sec-lead@example.com", "ciso@example.com"],
//     "quorum": "any",  // any | all | m_of_n
//     "quorum_n": 2,
//     "timeout_minutes": 60,
//     "on_timeout": "abort"  // abort | proceed | branch
//     "message": "Approve auto-isolation of ${ctx.host}?"
//   }
//
// Behavior: returns RunWaitingApproval status to caller (engine handles
// transition). Run is persisted; resume happens via separate API call to
// /approvals/{id}/decide.
//
// This executor BLOCKS waiting for resolver to report decision. Engine wires
// the resolver to read from playbook_approvals table.
// ─────────────────────────────────────────────────────────────────

// ApprovalRequest — what executor returns to engine on first call.
type ApprovalRequest struct {
	NodeID         string   `json:"node_id"`
	Approvers      []string `json:"approvers"`
	Quorum         string   `json:"quorum"`
	QuorumN        int      `json:"quorum_n"`
	TimeoutMinutes int      `json:"timeout_minutes"`
	OnTimeout      string   `json:"on_timeout"`
	Message        string   `json:"message"`
}

// ApprovalDecisionResolver — engine impl checks DB for decisions.
type ApprovalDecisionResolver interface {
	// CreateApproval persists request, returns approval ID.
	CreateApproval(ctx context.Context, runID string, req *ApprovalRequest) (approvalID string, err error)
	// PollDecision returns (decision, decided), where decided=false means still pending.
	PollDecision(ctx context.Context, approvalID string) (decision string, decided bool, err error)
}

type approvalExecutor struct {
	resolver ApprovalDecisionResolver
}

// NewApprovalExecutor — pass DB-backed resolver for production.
func NewApprovalExecutor(r ApprovalDecisionResolver) StepExecutor {
	return &approvalExecutor{resolver: r}
}

type approvalConfig struct {
	Approvers      []string `json:"approvers"`
	Quorum         string   `json:"quorum,omitempty"`
	QuorumN        int      `json:"quorum_n,omitempty"`
	TimeoutMinutes int      `json:"timeout_minutes,omitempty"`
	OnTimeout      string   `json:"on_timeout,omitempty"`
	Message        string   `json:"message,omitempty"`
}

// ErrApprovalPending — sentinel meaning run should park.
var ErrApprovalPending = errors.New("approval: pending human decision")

func (e *approvalExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg, err := parseConfig[approvalConfig](n)
	if err != nil {
		return nil, "", err
	}
	if len(cfg.Approvers) == 0 {
		return nil, "", fmt.Errorf("approval: approvers required")
	}
	if cfg.Quorum == "" {
		cfg.Quorum = "any"
	}
	if cfg.QuorumN == 0 {
		cfg.QuorumN = 1
	}
	if cfg.TimeoutMinutes == 0 {
		cfg.TimeoutMinutes = 60
	}
	if cfg.OnTimeout == "" {
		cfg.OnTimeout = "abort"
	}

	cfg.Message = resolveTemplate(cfg.Message, ec, ctx)

	if ec.IsTest || e.resolver == nil {
		// Test mode: auto-approve immediately
		result := map[string]interface{}{
			"_test_mode": ec.IsTest,
			"decision":   "approved",
			"auto":       true,
			"approvers":  cfg.Approvers,
		}
		out, err := json.Marshal(result)
		return out, "", err
	}

	req := &ApprovalRequest{
		NodeID:         n.ID,
		Approvers:      cfg.Approvers,
		Quorum:         cfg.Quorum,
		QuorumN:        cfg.QuorumN,
		TimeoutMinutes: cfg.TimeoutMinutes,
		OnTimeout:      cfg.OnTimeout,
		Message:        cfg.Message,
	}
	approvalID, err := e.resolver.CreateApproval(ctx, ec.RunID, req)
	if err != nil {
		return nil, "", fmt.Errorf("approval: create: %w", err)
	}

	// Engine handles parking; this executor returns sentinel error
	// with approval ID embedded in output for engine to read.
	result := map[string]interface{}{
		"approval_id": approvalID,
		"approvers":   cfg.Approvers,
		"message":     cfg.Message,
		"timeout_at":  time.Now().Add(time.Duration(cfg.TimeoutMinutes) * time.Minute).Format(time.RFC3339),
	}
	out, _ := json.Marshal(result)
	return out, "", ErrApprovalPending
}

// ─────────────────────────────────────────────────────────────────
// sub_playbook — invoke another playbook as a single step
//
// Config: {"playbook_id":"uuid","pass_context":true,"override_context":{...}}
//
// Recursive execution with depth limit (MaxRecursionDepth = 5).
// ─────────────────────────────────────────────────────────────────

// SubPlaybookExecutor delegates to engine for sub-execution.
// We use an interface so steps_flow.go doesn't depend on engine.go.
type SubPlaybookRunner interface {
	RunSub(ctx context.Context, parentEC *ExecCtx, playbookID string, overrides map[string]interface{}) (json.RawMessage, error)
}

type subPlaybookExecutor struct {
	runner SubPlaybookRunner
}

func NewSubPlaybookExecutor(r SubPlaybookRunner) StepExecutor {
	return &subPlaybookExecutor{runner: r}
}

type subPlaybookConfig struct {
	PlaybookID      string                 `json:"playbook_id"`
	PassContext     bool                   `json:"pass_context"`
	OverrideContext map[string]interface{} `json:"override_context"`
}

func (e *subPlaybookExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg, err := parseConfig[subPlaybookConfig](n)
	if err != nil {
		return nil, "", err
	}
	if cfg.PlaybookID == "" {
		return nil, "", fmt.Errorf("sub_playbook: playbook_id required")
	}
	if ec.Depth >= MaxRecursionDepth {
		return nil, "", fmt.Errorf("sub_playbook: recursion depth %d exceeds max %d", ec.Depth, MaxRecursionDepth)
	}

	if ec.IsTest || e.runner == nil {
		mock := map[string]interface{}{
			"_test_mode":      ec.IsTest,
			"sub_playbook_id": cfg.PlaybookID,
			"would_invoke":    true,
		}
		out, err := json.Marshal(mock)
		return out, "", err
	}

	out, err := e.runner.RunSub(ctx, ec, cfg.PlaybookID, cfg.OverrideContext)
	if err != nil {
		return nil, "", fmt.Errorf("sub_playbook: %w", err)
	}
	return out, "", nil
}

// ─────────────────────────────────────────────────────────────────
// fork — marker step. Engine reads node.Branches and spawns goroutines.
//
// Config: {"branches":["n_a","n_b","n_c"],"join_node":"n_join","max_parallel":3}
//
// Executor itself just records the plan; engine handles concurrency.
// ─────────────────────────────────────────────────────────────────

type forkExecutor struct{}

type forkConfig struct {
	Branches    []string `json:"branches"`
	JoinNode    string   `json:"join_node"`
	MaxParallel int      `json:"max_parallel,omitempty"`
}

func (e *forkExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg, err := parseConfig[forkConfig](n)
	if err != nil {
		return nil, "", err
	}
	// Allow node-level fields as fallback (set by graph migration / UI)
	if len(cfg.Branches) == 0 {
		cfg.Branches = n.Branches
	}
	if cfg.JoinNode == "" {
		cfg.JoinNode = n.JoinNode
	}
	if len(cfg.Branches) == 0 {
		return nil, "", fmt.Errorf("fork: branches required")
	}
	if cfg.JoinNode == "" {
		return nil, "", fmt.Errorf("fork: join_node required")
	}
	if cfg.MaxParallel <= 0 {
		cfg.MaxParallel = len(cfg.Branches)
	}

	result := map[string]interface{}{
		"branches":     cfg.Branches,
		"join_node":    cfg.JoinNode,
		"max_parallel": cfg.MaxParallel,
		"_marker":      "fork",
	}
	out, err := json.Marshal(result)
	return out, "", err
}

// ─────────────────────────────────────────────────────────────────
// join — marker step. Engine merges branches results.
// ─────────────────────────────────────────────────────────────────

type joinExecutor struct{}

func (e *joinExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	result := map[string]interface{}{
		"_marker":   "join",
		"joined_at": time.Now().UTC().Format(time.RFC3339),
	}
	out, err := json.Marshal(result)
	return out, "", err
}

// ─────────────────────────────────────────────────────────────────
// Helper: register all I/O + flow executors into a Dispatcher
// ─────────────────────────────────────────────────────────────────

// RegisterIOExecutors adds http, notify, ticket to dispatcher.
// Pass nil for any service to make those steps test-mode-only (mock output).
func RegisterIOExecutors(d *Dispatcher, http HTTPDoer, notify Notifier, ticket Ticketer) {
	d.Register(StepHTTP, NewHTTPExecutor(http))
	d.Register(StepNotify, NewNotifyExecutor(notify))
	d.Register(StepTicket, NewTicketExecutor(ticket))
}

// RegisterFlowExecutors adds script, approval, sub_playbook, fork, join.
func RegisterFlowExecutors(d *Dispatcher, sandbox *Sandbox, approver ApprovalDecisionResolver, sub SubPlaybookRunner) {
	d.Register(StepScript, NewScriptExecutor(sandbox))
	d.Register(StepApproval, NewApprovalExecutor(approver))
	d.Register(StepSubPlaybook, NewSubPlaybookExecutor(sub))
	d.Register(StepFork, &forkExecutor{})
	d.Register(StepJoin, &joinExecutor{})
}
