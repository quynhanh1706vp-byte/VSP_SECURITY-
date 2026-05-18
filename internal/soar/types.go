// Package soar — Security Orchestration, Automation & Response engine.
//
// Architecture:
//
//	HTTP handler  →  Engine.Execute(playbook, trigger)
//	                       ↓
//	                  Validator (graph check)
//	                       ↓
//	                  Manager (run persistence + SSE)
//	                       ↓
//	                  Executor (DAG topo + parallel)
//	                       ↓
//	                  Step dispatch by type
//	                       ↓
//	                  Sandbox / HTTP / Notify / Approval / ...
//
// Key invariants:
//
//   - Every Run is tenant-scoped. No cross-tenant leakage.
//   - Secrets are decrypted just-in-time and wiped after step.
//   - Step output is always JSON-serializable (or rejected).
//   - Graph must be a DAG. Cycles are rejected at Validate().
package soar

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ─────────────────────────────────────────────────────────────────
// Step types — compile-time enum
// ─────────────────────────────────────────────────────────────────

// StepType — enum of all supported step types.
type StepType string

const (
	// Modern types (DAG-aware)
	StepCondition   StepType = "condition" // if/else branch
	StepFork        StepType = "fork"      // parallel branches
	StepJoin        StepType = "join"      // wait for fork branches
	StepHTTP        StepType = "http"      // HTTP call with retry
	StepScript      StepType = "script"    // Goja JS sandbox
	StepNotify      StepType = "notify"    // Slack/email/teams/webhook
	StepTicket      StepType = "ticket"    // Jira/GitHub/ServiceNow
	StepApproval    StepType = "approval"  // human gate
	StepSubPlaybook StepType = "sub_playbook"
	StepLoop        StepType = "loop"    // for_each over array
	StepWait        StepType = "wait"    // sleep / until
	StepSetVar      StepType = "set_var" // store value in ctx
	StepEnd         StepType = "end"     // terminator (optional)

	// Legacy compat (from existing 4 playbooks)
	StepEnrich    StepType = "enrich"    // → enrich CVE/IOC via threat_intel
	StepBlock     StepType = "block"     // → block CI pipeline (GitHub status)
	StepRemediate StepType = "remediate" // → update remediations table
)

// IsValid reports whether t is a known step type.
func (t StepType) IsValid() bool {
	switch t {
	case StepCondition, StepFork, StepJoin, StepHTTP, StepScript,
		StepNotify, StepTicket, StepApproval, StepSubPlaybook,
		StepLoop, StepWait, StepSetVar, StepEnd,
		StepEnrich, StepBlock, StepRemediate:
		return true
	}
	return false
}

// IsLegacy reports whether t is from the legacy step taxonomy.
func (t StepType) IsLegacy() bool {
	switch t {
	case StepEnrich, StepBlock, StepRemediate:
		return true
	}
	return false
}

// ─────────────────────────────────────────────────────────────────
// Graph — DAG definition
// ─────────────────────────────────────────────────────────────────

// Graph is the DAG defining a playbook's execution flow.
type Graph struct {
	Nodes    []Node          `json:"nodes"`
	Edges    [][2]string     `json:"edges"`              // [[fromID, toID], ...]
	Entry    string          `json:"entry,omitempty"`    // entry node ID; defaults to nodes[0].ID
	Metadata json.RawMessage `json:"metadata,omitempty"` // free-form
}

// Node is one step in the graph.
type Node struct {
	ID             string          `json:"id"`
	Type           StepType        `json:"type"`
	Name           string          `json:"name"`
	Description    string          `json:"description,omitempty"`
	Config         json.RawMessage `json:"config,omitempty"`     // type-specific JSON config
	ConfigRaw      string          `json:"config_raw,omitempty"` // legacy YAML-string
	OnFailure      OnFailure       `json:"on_failure,omitempty"` // default: abort
	OnFailureNext  string          `json:"on_failure_next,omitempty"`
	Retry          *RetryPolicy    `json:"retry,omitempty"`
	TimeoutSeconds int             `json:"timeout_seconds,omitempty"` // 0 = engine default

	// Branch-specific (set by parser/migration)
	NextTrue  string   `json:"next_true,omitempty"`  // condition: if expr=true
	NextFalse string   `json:"next_false,omitempty"` // condition: if expr=false
	Branches  []string `json:"branches,omitempty"`   // fork: parallel start nodes
	JoinNode  string   `json:"join_node,omitempty"`  // fork: where branches converge
}

// OnFailure dictates what to do when a step fails (after all retries).
type OnFailure string

const (
	OnFailAbort    OnFailure = "abort"    // stop entire run (default)
	OnFailContinue OnFailure = "continue" // proceed to next normal node
	OnFailBranch   OnFailure = "branch"   // jump to OnFailureNext
)

// RetryPolicy controls per-step retry behavior.
type RetryPolicy struct {
	Max         int     `json:"max"`          // attempts after first failure (0 = no retry)
	Backoff     Backoff `json:"backoff"`      // exponential | linear | fixed
	BaseMS      int     `json:"base_ms"`      // base delay
	MaxMS       int     `json:"max_ms"`       // cap (for exponential)
	JitterRatio float64 `json:"jitter_ratio"` // 0.0..1.0, fraction of delay to randomize
}

// Backoff strategy.
type Backoff string

const (
	BackoffFixed       Backoff = "fixed"
	BackoffLinear      Backoff = "linear"
	BackoffExponential Backoff = "exponential"
)

// ─────────────────────────────────────────────────────────────────
// Playbook — top-level
// ─────────────────────────────────────────────────────────────────

// Playbook represents a saved playbook definition (mirrors DB row).
type Playbook struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	TriggerEvent   string          `json:"trigger_event"`
	TriggerFilter  json.RawMessage `json:"trigger_filter"`
	Graph          Graph           `json:"graph"`
	Status         string          `json:"status"` // draft | enabled | disabled | archived
	Version        int             `json:"version"`
	SecretRefs     []string        `json:"secret_refs"`
	Tags           []string        `json:"tags"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	MaxRetries     int             `json:"max_retries"`
	RunCount       int             `json:"run_count"`
	SuccessCount   int             `json:"success_count"`
	CreatedAt      time.Time       `json:"created_at"`
	CreatedBy      string          `json:"created_by"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// ─────────────────────────────────────────────────────────────────
// Run — execution instance
// ─────────────────────────────────────────────────────────────────

// RunStatus lifecycle.
type RunStatus string

const (
	RunPending         RunStatus = "pending"
	RunRunning         RunStatus = "running"
	RunSuccess         RunStatus = "success"
	RunFailed          RunStatus = "failed"
	RunCancelled       RunStatus = "cancelled"
	RunTimeout         RunStatus = "timeout"
	RunWaitingApproval RunStatus = "waiting_approval"
	RunPartial         RunStatus = "partial"
)

// Run records a single execution.
type Run struct {
	ID              string          `json:"id"`
	PlaybookID      string          `json:"playbook_id"`
	PlaybookVersion int             `json:"playbook_version"`
	TenantID        string          `json:"tenant_id"`
	Status          RunStatus       `json:"status"`
	Trigger         string          `json:"trigger"`
	TriggeredBy     string          `json:"triggered_by"`
	IsTest          bool            `json:"is_test"`
	Context         json.RawMessage `json:"context"`
	StepResults     []StepResult    `json:"step_results"`
	CurrentNode     string          `json:"current_node"`
	Error           string          `json:"error,omitempty"`
	StartedAt       time.Time       `json:"started_at"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	DurationMS      int             `json:"duration_ms"`
}

// StepResult captures one step's execution outcome.
type StepResult struct {
	NodeID     string          `json:"node_id"`
	Type       StepType        `json:"type"`
	Name       string          `json:"name"`
	Status     StepStatus      `json:"status"`
	Output     json.RawMessage `json:"output,omitempty"`
	Error      string          `json:"error,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	DurationMS int             `json:"duration_ms"`
	Attempts   int             `json:"attempts"`
}

// StepStatus per-step lifecycle.
type StepStatus string

const (
	StepRunning StepStatus = "running"
	StepDone    StepStatus = "done"
	StepFailed  StepStatus = "failed"
	StepSkipped StepStatus = "skipped" // not executed (branch not taken)
	StepWaiting StepStatus = "waiting" // approval pending
	StepTimeout StepStatus = "timeout"
)

// ─────────────────────────────────────────────────────────────────
// ExecCtx — runtime execution context (per-run, mutable)
// ─────────────────────────────────────────────────────────────────

// ExecCtx is the context passed between step executors. NOT goroutine-safe
// for concurrent fork branches — Engine snapshots/merges per-branch ctx.
type ExecCtx struct {
	RunID      string
	PlaybookID string
	TenantID   string
	IsTest     bool

	// Vars: trigger payload + accumulated set_var outputs.
	Vars map[string]interface{}

	// StepOutputs: completed step outputs by node ID. Read-only inside steps.
	StepOutputs map[string]json.RawMessage

	// SecretsResolver — looks up by name. Implementations MUST audit-log access.
	Secrets SecretsResolver

	// HTTPClient with SSRF guard. nil → engine provides default.
	HTTPClient HTTPDoer

	// Recursion depth (sub_playbook protection)
	Depth int

	// Cancellation
	Ctx context.Context
}

// SecretsResolver retrieves a decrypted secret value by name.
// Implementation MUST log access and never expose plaintext via toString.
type SecretsResolver interface {
	Resolve(ctx context.Context, name string) (string, error)
}

// HTTPDoer abstracts http.Client for testability.
type HTTPDoer interface {
	Do(req *HTTPReq) (*HTTPResp, error)
}

// HTTPReq — abstract HTTP request (engine builds, doer executes).
type HTTPReq struct {
	Method         string
	URL            string
	Headers        map[string]string
	Body           []byte
	TimeoutSeconds int
}

// HTTPResp — abstract HTTP response.
type HTTPResp struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

// ─────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────

// EngineError wraps step-level errors with node context.
type EngineError struct {
	NodeID  string
	Step    StepType
	Wrapped error
}

func (e *EngineError) Error() string {
	return fmt.Sprintf("soar: node %q (%s): %v", e.NodeID, e.Step, e.Wrapped)
}

func (e *EngineError) Unwrap() error { return e.Wrapped }

// Resource / safety limits (engine constants).
const (
	MaxNodesPerGraph    = 100
	MaxRecursionDepth   = 5
	MaxRunDurationSec   = 300
	MaxStepDurationSec  = 60
	MaxScriptOutputSize = 1 * 1024 * 1024 // 1MB
	MaxLoopIterations   = 1000
)

// StepExecutor implements the execution logic for one step type.
// All executors share a single Run() signature for uniform dispatch.
//
// Returns:
//   - output: JSON-encoded step output (will appear in steps[node.id])
//   - nextNode: optional override of next node (for condition / on_failure)
//     empty string means: follow normal outgoing edges
//   - err: nil on success, non-nil to trigger retry/abort/branch handling
type StepExecutor interface {
	Run(ctx context.Context, node *Node, ec *ExecCtx) (output json.RawMessage, nextNode string, err error)
}
