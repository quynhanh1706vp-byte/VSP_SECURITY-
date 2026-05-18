package soar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// Engine — the heart of SOAR. Executes a validated graph as a DAG with
// support for parallel forks, conditional branches, loops, and approvals.
//
// Lifecycle of a run:
//
//  1. Validate graph (cycle/reachability/types)
//  2. Build ExecCtx with secrets resolver bound to run
//  3. Persist run record (status=running)
//  4. Spawn goroutine that walks DAG via topological order
//  5. For each node:
//       - Apply retry policy
//       - Dispatch to executor (sandbox/HTTP/notify/...)
//       - Persist step result (live progress)
//       - Broadcast SSE event
//       - Handle on_failure (abort/continue/branch)
//  6. On approval pending: park run as 'waiting_approval', resume on poll
//  7. Final status: success | failed | timeout | cancelled
// ════════════════════════════════════════════════════════════════════

// Engine is the top-level executor. Stateless across calls — safe to share.
type Engine struct {
	store       EngineStore
	dispatcher  *Dispatcher
	vault       *Vault
	sandbox     *Sandbox
	broadcaster Broadcaster

	maxConcurrent  int
	stepTimeout    time.Duration
	runTimeout     time.Duration
	approvalPollMS int

	// Concurrency limit — semaphore (acquire before spawn, release on finish)
	sem chan struct{}

	// Metrics — emit counters/gauges/histograms; nil-safe via noopMetrics
	metrics Metrics

	// runRegistry — runID → cancel func, for Cancel()
	runMu       sync.RWMutex
	runRegistry map[string]context.CancelFunc
}

// EngineStore — minimal store interface engine needs. Implemented by *store.DB.
type EngineStore interface {
	// Playbook
	GetPlaybook(ctx context.Context, tenantID, id string) (*Playbook, error)

	// Runs
	CreateRun(ctx context.Context, p CreateRunArgs) (runID string, startedAt time.Time, err error)
	UpdateRunStatus(ctx context.Context, runID, status, currentNode string) error
	UpdateRunResults(ctx context.Context, runID string, stepResults json.RawMessage, errMsg string) error
	FinishRun(ctx context.Context, runID, status string, durationMS int) error

	// Approval polling (impl ApprovalDecisionResolver)
	CreateApproval(ctx context.Context, runID string, req *ApprovalRequest) (string, error)
	PollDecision(ctx context.Context, approvalID string) (string, bool, error)
}

// CreateRunArgs — what engine passes to store.
type CreateRunArgs struct {
	PlaybookID      string
	PlaybookVersion int
	TenantID        string
	TriggerEvent    string
	TriggeredBy     string
	IsTest          bool
	Context         json.RawMessage
}

// Broadcaster — sends progress events. Used for SSE; nil means no broadcast.
type Broadcaster interface {
	Broadcast(msg []byte)
}

// EngineConfig — Engine construction options. All fields optional.
type EngineConfig struct {
	Store          EngineStore
	Dispatcher     *Dispatcher // must be pre-populated with executors
	Vault          *Vault      // for secrets resolution
	Sandbox        *Sandbox    // shared sandbox
	Broadcaster    Broadcaster // SSE broker
	Metrics        Metrics     // optional; nil → no-op
	MaxConcurrent  int         // per-engine cap
	StepTimeout    time.Duration
	RunTimeout     time.Duration
	ApprovalPollMS int
}

// New constructs an Engine. cfg.Store and cfg.Dispatcher are required.
func New(cfg EngineConfig) (*Engine, error) {
	if cfg.Store == nil {
		return nil, errors.New("engine: store required")
	}
	if cfg.Dispatcher == nil {
		return nil, errors.New("engine: dispatcher required")
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 100
	}
	if cfg.StepTimeout <= 0 {
		cfg.StepTimeout = time.Duration(MaxStepDurationSec) * time.Second
	}
	if cfg.RunTimeout <= 0 {
		cfg.RunTimeout = time.Duration(MaxRunDurationSec) * time.Second
	}
	if cfg.ApprovalPollMS <= 0 {
		cfg.ApprovalPollMS = 2000
	}
	if cfg.Sandbox == nil {
		cfg.Sandbox = NewSandbox()
	}
	metrics := cfg.Metrics
	if metrics == nil {
		metrics = noopMetrics{}
	}
	return &Engine{
		store:          cfg.Store,
		dispatcher:     cfg.Dispatcher,
		vault:          cfg.Vault,
		sandbox:        cfg.Sandbox,
		broadcaster:    cfg.Broadcaster,
		maxConcurrent:  cfg.MaxConcurrent,
		stepTimeout:    cfg.StepTimeout,
		runTimeout:     cfg.RunTimeout,
		approvalPollMS: cfg.ApprovalPollMS,
		metrics:        metrics,
		sem:            make(chan struct{}, cfg.MaxConcurrent),
		runRegistry:    make(map[string]context.CancelFunc),
	}, nil
}

// ExecuteOptions — per-run overrides.
type ExecuteOptions struct {
	IsTest       bool
	TriggerEvent string
	TriggeredBy  string
	Context      map[string]interface{} // initial vars
	Async        bool                   // if false (default), wait for completion
}

// Execute runs a playbook. If opts.Async, returns immediately with run record;
// caller polls run status. If sync (default), blocks until terminal state.
func (e *Engine) Execute(ctx context.Context, pb *Playbook, opts ExecuteOptions) (*Run, error) {
	if pb == nil {
		return nil, errors.New("engine: nil playbook")
	}
	if err := Validate(&pb.Graph); err != nil {
		return nil, fmt.Errorf("engine: invalid graph: %w", err)
	}

	if opts.TriggerEvent == "" {
		opts.TriggerEvent = "manual"
	}
	if opts.TriggeredBy == "" {
		opts.TriggeredBy = "system"
	}

	ctxJSON, _ := json.Marshal(opts.Context)
	if len(ctxJSON) == 0 {
		ctxJSON = json.RawMessage(`{}`)
	}

	// Acquire concurrency slot (DoS protection)
	select {
	case e.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	e.metrics.GaugeSet(MetricActiveRuns, nil, float64(len(e.sem)))

	runID, startedAt, err := e.store.CreateRun(ctx, CreateRunArgs{
		PlaybookID:      pb.ID,
		PlaybookVersion: pb.Version,
		TenantID:        pb.TenantID,
		TriggerEvent:    opts.TriggerEvent,
		TriggeredBy:     opts.TriggeredBy,
		IsTest:          opts.IsTest,
		Context:         ctxJSON,
	})
	if err != nil {
		<-e.sem // release slot
		return nil, fmt.Errorf("engine: create run: %w", err)
	}

	run := &Run{
		ID:              runID,
		PlaybookID:      pb.ID,
		PlaybookVersion: pb.Version,
		TenantID:        pb.TenantID,
		Status:          RunRunning,
		Trigger:         opts.TriggerEvent,
		TriggeredBy:     opts.TriggeredBy,
		IsTest:          opts.IsTest,
		Context:         ctxJSON,
		StepResults:     []StepResult{},
		StartedAt:       startedAt,
	}

	e.broadcastEvent("soar:run:start", map[string]interface{}{
		"run_id":      runID,
		"playbook_id": pb.ID,
		"trigger":     opts.TriggerEvent,
	})

	// Build ExecCtx
	runCtx, cancel := context.WithTimeout(ctx, e.runTimeout)
	e.runMu.Lock()
	e.runRegistry[runID] = cancel
	e.runMu.Unlock()

	ec := &ExecCtx{
		RunID:       runID,
		PlaybookID:  pb.ID,
		TenantID:    pb.TenantID,
		IsTest:      opts.IsTest,
		Vars:        opts.Context,
		StepOutputs: make(map[string]json.RawMessage),
		Depth:       0,
		Ctx:         runCtx,
	}
	if opts.Context == nil {
		ec.Vars = make(map[string]interface{})
	}
	if e.vault != nil {
		ec.Secrets = e.vault.Resolver(pb.TenantID, runID, opts.TriggeredBy)
	}

	if opts.Async {
		go func() {
			defer cancel()
			defer e.deregister(runID)
			e.executeDAG(runCtx, pb, ec, run)
		}()
		return run, nil
	}

	// Sync execution
	defer cancel()
	defer e.deregister(runID)
	e.executeDAG(runCtx, pb, ec, run)
	return run, nil
}

// Cancel aborts a running run.
func (e *Engine) Cancel(runID string) error {
	e.runMu.RLock()
	cancel, ok := e.runRegistry[runID]
	e.runMu.RUnlock()
	if !ok {
		return fmt.Errorf("engine: run %s not active", runID)
	}
	cancel()
	return nil
}

func (e *Engine) deregister(runID string) {
	e.runMu.Lock()
	delete(e.runRegistry, runID)
	e.runMu.Unlock()
	// Release semaphore slot
	select {
	case <-e.sem:
	default:
	}
	e.metrics.GaugeSet(MetricActiveRuns, nil, float64(len(e.sem)))
}

// ─────────────────────────────────────────────────────────────────
// DAG executor
// ─────────────────────────────────────────────────────────────────

// executeDAG walks the graph from entry, executing nodes per topological
// order, handling forks via parallel goroutines and joins via errgroup-like
// wait pattern.
func (e *Engine) executeDAG(ctx context.Context, pb *Playbook, ec *ExecCtx, run *Run) {
	startTime := time.Now()
	defer func() {
		duration := int(time.Since(startTime).Milliseconds())
		_ = e.store.FinishRun(context.Background(), run.ID, string(run.Status), duration)
		run.DurationMS = duration
		now := time.Now()
		run.FinishedAt = &now

		// Metrics: counter + duration histogram
		labels := map[string]string{"status": string(run.Status)}
		e.metrics.CounterAdd(MetricRunsTotal, labels, 1)
		e.metrics.HistogramObserve(MetricRunDurationMS, labels, float64(duration))

		e.broadcastEvent("soar:run:end", map[string]interface{}{
			"run_id":      run.ID,
			"status":      run.Status,
			"duration_ms": duration,
			"error":       run.Error,
		})
	}()

	// Determine entry node
	entry := pb.Graph.Entry
	if entry == "" && len(pb.Graph.Nodes) > 0 {
		entry = pb.Graph.Nodes[0].ID
	}
	if entry == "" {
		run.Status = RunFailed
		run.Error = "graph has no entry"
		return
	}

	// Build node lookup + adjacency for next-resolution
	nodeMap := make(map[string]*Node, len(pb.Graph.Nodes))
	adj := make(map[string][]string, len(pb.Graph.Nodes))
	for i := range pb.Graph.Nodes {
		n := &pb.Graph.Nodes[i]
		nodeMap[n.ID] = n
	}
	for _, edge := range pb.Graph.Edges {
		adj[edge[0]] = append(adj[edge[0]], edge[1])
	}

	// Linear walk: starting from entry, follow edges + branch overrides.
	// For fork: spawn goroutines per branch, wait at join.
	if err := e.walkLinear(ctx, ec, run, nodeMap, adj, entry, ""); err != nil {
		// Check sentinel: approval pending
		if errors.Is(err, ErrApprovalPending) {
			run.Status = RunWaitingApproval
			run.Error = ""
			_ = e.store.UpdateRunStatus(ctx, run.ID, string(RunWaitingApproval), run.CurrentNode)
			return
		}
		// Check ctx cancel
		if errors.Is(err, context.Canceled) {
			run.Status = RunCancelled
			run.Error = "cancelled"
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			run.Status = RunTimeout
			run.Error = "run timeout"
			return
		}
		run.Status = RunFailed
		run.Error = err.Error()
		return
	}
	run.Status = RunSuccess
}

// walkLinear walks from `start` until it hits a terminal node or an unwalked
// fork. `stopAt` is a join node ID — when set, walk stops at that node (used
// by branch goroutines so they don't continue past join).
func (e *Engine) walkLinear(ctx context.Context, ec *ExecCtx, run *Run,
	nodeMap map[string]*Node, adj map[string][]string,
	current, stopAt string) error {

	visited := make(map[string]bool)

	for current != "" && current != stopAt {
		if err := ctx.Err(); err != nil {
			return err
		}
		if visited[current] {
			return fmt.Errorf("walk: revisited node %s (cycle slipped past validator)", current)
		}
		visited[current] = true

		node, ok := nodeMap[current]
		if !ok {
			return fmt.Errorf("walk: node %s not found", current)
		}
		run.CurrentNode = current
		_ = e.store.UpdateRunStatus(context.Background(), run.ID, string(RunRunning), current)

		// Special handling for fork: parallel execution
		if node.Type == StepFork {
			next, err := e.handleFork(ctx, ec, run, nodeMap, adj, node)
			if err != nil {
				return err
			}
			current = next
			continue
		}

		// Special handling for loop: iterate body
		if node.Type == StepLoop {
			next, err := e.handleLoop(ctx, ec, run, nodeMap, adj, node)
			if err != nil {
				return err
			}
			current = next
			continue
		}

		// Standard step execution
		stepRes, nextOverride, err := e.executeStep(ctx, ec, node)
		run.StepResults = append(run.StepResults, *stepRes)
		e.persistStepResults(run)

		e.broadcastEvent("soar:step:done", map[string]interface{}{
			"run_id":      run.ID,
			"node_id":     node.ID,
			"status":      stepRes.Status,
			"duration_ms": stepRes.DurationMS,
		})

		if err != nil {
			// Approval pending bubbles up
			if errors.Is(err, ErrApprovalPending) {
				return err
			}

			// Apply on_failure policy
			switch node.OnFailure {
			case OnFailContinue:
				// log and proceed normally
			case OnFailBranch:
				if node.OnFailureNext != "" {
					current = node.OnFailureNext
					continue
				}
				return err
			default: // OnFailAbort
				return err
			}
		}

		// Determine next node
		if nextOverride != "" {
			current = nextOverride
			continue
		}
		if node.Type == StepEnd {
			return nil
		}
		// Pick first outgoing edge (linear chains)
		nexts := adj[current]
		if len(nexts) == 0 {
			return nil // graph ended
		}
		current = nexts[0]
	}
	return nil
}

// handleFork spawns goroutines for each branch, waits at join.
// Branch goroutines walk independently, with stopAt = join_node.
// Step outputs and vars are merged (last-write-wins for vars; no merge issue
// for step outputs since each branch writes distinct node IDs).
func (e *Engine) handleFork(ctx context.Context, ec *ExecCtx, run *Run,
	nodeMap map[string]*Node, adj map[string][]string, fork *Node) (string, error) {

	// Execute fork executor itself (records plan)
	stepRes, _, err := e.executeStep(ctx, ec, fork)
	run.StepResults = append(run.StepResults, *stepRes)
	e.persistStepResults(run)
	if err != nil {
		return "", err
	}

	branches := fork.Branches
	joinNode := fork.JoinNode
	if len(branches) == 0 || joinNode == "" {
		// Try parsing from output
		var plan struct {
			Branches []string `json:"branches"`
			JoinNode string   `json:"join_node"`
		}
		_ = json.Unmarshal(stepRes.Output, &plan)
		branches = plan.Branches
		joinNode = plan.JoinNode
	}
	if len(branches) == 0 || joinNode == "" {
		return "", fmt.Errorf("fork: missing branches or join_node")
	}

	// Mutex for shared state (StepOutputs, Vars, run.StepResults)
	var mu sync.Mutex
	errCh := make(chan error, len(branches))

	for _, branchStart := range branches {
		go func(start string) {
			// Per-branch ec snapshot — share output map but lock writes
			branchCtx := *ec
			branchCtx.StepOutputs = ec.StepOutputs // shared

			// Wrap walkLinear with mutex on persist
			err := e.walkBranch(ctx, &branchCtx, run, nodeMap, adj, start, joinNode, &mu)
			errCh <- err
		}(branchStart)
	}

	for i := 0; i < len(branches); i++ {
		if err := <-errCh; err != nil {
			return "", fmt.Errorf("fork branch failed: %w", err)
		}
	}

	// Continue from join
	return joinNode, nil
}

// walkBranch is walkLinear but writes to run.StepResults under mutex.
func (e *Engine) walkBranch(ctx context.Context, ec *ExecCtx, run *Run,
	nodeMap map[string]*Node, adj map[string][]string,
	start, stopAt string, mu *sync.Mutex) error {

	visited := make(map[string]bool)
	current := start

	for current != "" && current != stopAt {
		if err := ctx.Err(); err != nil {
			return err
		}
		if visited[current] {
			return fmt.Errorf("walk: revisited %s in branch", current)
		}
		visited[current] = true

		node, ok := nodeMap[current]
		if !ok {
			return fmt.Errorf("branch: node %s not found", current)
		}

		stepRes, nextOverride, err := e.executeStep(ctx, ec, node)

		mu.Lock()
		run.StepResults = append(run.StepResults, *stepRes)
		e.persistStepResults(run)
		mu.Unlock()

		if err != nil {
			if node.OnFailure == OnFailContinue {
				// proceed
			} else if node.OnFailure == OnFailBranch && node.OnFailureNext != "" {
				current = node.OnFailureNext
				continue
			} else {
				return err
			}
		}

		if nextOverride != "" {
			current = nextOverride
			continue
		}
		nexts := adj[current]
		if len(nexts) == 0 {
			return nil
		}
		current = nexts[0]
	}
	return nil
}

// handleLoop executes the body node once per item.
func (e *Engine) handleLoop(ctx context.Context, ec *ExecCtx, run *Run,
	nodeMap map[string]*Node, adj map[string][]string, loop *Node) (string, error) {

	stepRes, _, err := e.executeStep(ctx, ec, loop)
	run.StepResults = append(run.StepResults, *stepRes)
	e.persistStepResults(run)
	if err != nil {
		return "", err
	}

	var plan LoopPlan
	if err := json.Unmarshal(stepRes.Output, &plan); err != nil {
		return "", fmt.Errorf("loop: parse plan: %w", err)
	}

	bodyNode, ok := nodeMap[plan.Body]
	if !ok {
		return "", fmt.Errorf("loop: body %s not found", plan.Body)
	}

	for i, item := range plan.Items {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		// Set item var
		if ec.Vars == nil {
			ec.Vars = make(map[string]interface{})
		}
		ec.Vars[plan.ItemVar] = item
		ec.Vars["_loop_index"] = i

		// Execute body (single node, not full sub-walk)
		bodyRes, _, err := e.executeStep(ctx, ec, bodyNode)
		bodyRes.NodeID = fmt.Sprintf("%s[%d]", bodyNode.ID, i)
		run.StepResults = append(run.StepResults, *bodyRes)
		e.persistStepResults(run)
		if err != nil {
			return "", fmt.Errorf("loop iteration %d: %w", i, err)
		}
	}

	// Continue from edge after loop
	nexts := adj[loop.ID]
	if len(nexts) == 0 {
		return "", nil // loop is terminal
	}
	// Skip body in normal walk (already consumed inside loop)
	for _, n := range nexts {
		if n != plan.Body {
			return n, nil
		}
	}
	return "", nil
}

// executeStep runs a single node with retry + timeout.
func (e *Engine) executeStep(ctx context.Context, ec *ExecCtx, node *Node) (*StepResult, string, error) {
	startTime := time.Now()
	res := &StepResult{
		NodeID:    node.ID,
		Type:      node.Type,
		Name:      node.Name,
		Status:    StepRunning,
		StartedAt: startTime,
		Attempts:  0,
	}

	// Per-step timeout
	stepTimeout := time.Duration(node.TimeoutSeconds) * time.Second
	if stepTimeout <= 0 {
		stepTimeout = e.stepTimeout
	}
	stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()

	var output json.RawMessage
	var nextOverride string

	policy := node.Retry
	if policy == nil {
		policy = &RetryPolicy{Max: 0}
	}

	err := Retry(stepCtx, policy, nil, func(ctx context.Context, attempt int) error {
		res.Attempts = attempt
		var dispErr error
		output, nextOverride, dispErr = e.dispatcher.Dispatch(ctx, node, ec)
		if dispErr != nil {
			return dispErr
		}
		// Save output to ec.StepOutputs for downstream steps
		if output != nil && ec.StepOutputs != nil {
			ec.StepOutputs[node.ID] = output
		}
		return nil
	})

	res.FinishedAt = time.Now()
	res.DurationMS = int(res.FinishedAt.Sub(res.StartedAt).Milliseconds())
	res.Output = output

	if err != nil {
		if errors.Is(err, ErrApprovalPending) {
			res.Status = StepWaiting
			e.emitStepMetrics(node, res)
			return res, nextOverride, err
		}
		if errors.Is(err, context.DeadlineExceeded) {
			res.Status = StepTimeout
		} else {
			res.Status = StepFailed
		}
		res.Error = err.Error()
		e.emitStepMetrics(node, res)
		return res, "", err
	}
	res.Status = StepDone
	e.emitStepMetrics(node, res)
	return res, nextOverride, nil
}

// emitStepMetrics records step counter + histogram + retry counter.
func (e *Engine) emitStepMetrics(node *Node, res *StepResult) {
	labels := map[string]string{
		"step_type": string(node.Type),
		"status":    string(res.Status),
	}
	e.metrics.CounterAdd(MetricStepsTotal, labels, 1)
	e.metrics.HistogramObserve(MetricStepDurationMS, labels, float64(res.DurationMS))
	if res.Attempts > 1 {
		e.metrics.CounterAdd(MetricRetryTotal,
			map[string]string{"step_type": string(node.Type)},
			uint64(res.Attempts-1))
	}
}

func (e *Engine) persistStepResults(run *Run) {
	data, _ := json.Marshal(run.StepResults)
	_ = e.store.UpdateRunResults(context.Background(), run.ID, data, run.Error)
}

func (e *Engine) broadcastEvent(event string, payload map[string]interface{}) {
	if e.broadcaster == nil {
		return
	}
	// Wrap legacy map-based call in typed Event for forward-compat
	evt := Event{Type: EventType(event), Timestamp: time.Now().UTC()}
	if v, ok := payload["run_id"].(string); ok {
		evt.RunID = v
	}
	if v, ok := payload["playbook_id"].(string); ok {
		evt.PlaybookID = v
	}
	if v, ok := payload["node_id"].(string); ok {
		evt.NodeID = v
	}
	if v, ok := payload["status"]; ok {
		switch s := v.(type) {
		case string:
			evt.Status = s
		case RunStatus:
			evt.Status = string(s)
		case StepStatus:
			evt.Status = string(s)
		}
	}
	if v, ok := payload["duration_ms"].(int); ok {
		evt.DurationMS = v
	}
	if v, ok := payload["error"].(string); ok {
		evt.Error = v
	}
	if v, ok := payload["trigger"].(string); ok {
		evt.Trigger = v
	}
	e.broadcaster.Broadcast(EncodeEvent(evt))
}

// emitEvent — typed event emission for new code paths.
func (e *Engine) emitEvent(evt Event) {
	if e.broadcaster == nil {
		return
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}
	e.broadcaster.Broadcast(EncodeEvent(evt))
}

// ─────────────────────────────────────────────────────────────────
// Sub-playbook support — implements SubPlaybookRunner
// ─────────────────────────────────────────────────────────────────

// RunSub is called by sub_playbook step. Loads target playbook, runs it,
// returns aggregated step output as JSON.
func (e *Engine) RunSub(ctx context.Context, parentEC *ExecCtx, playbookID string, ovr map[string]interface{}) (json.RawMessage, error) {
	if parentEC.Depth >= MaxRecursionDepth {
		return nil, fmt.Errorf("sub_playbook: depth %d exceeds %d", parentEC.Depth, MaxRecursionDepth)
	}

	subPB, err := e.store.GetPlaybook(ctx, parentEC.TenantID, playbookID)
	if err != nil {
		return nil, fmt.Errorf("sub_playbook: load: %w", err)
	}

	// Inherit context, allow overrides
	ctxMap := make(map[string]interface{})
	for k, v := range parentEC.Vars {
		ctxMap[k] = v
	}
	for k, v := range ovr {
		ctxMap[k] = v
	}

	subRun, err := e.Execute(ctx, subPB, ExecuteOptions{
		IsTest:       parentEC.IsTest,
		TriggerEvent: "sub_playbook",
		TriggeredBy:  parentEC.RunID,
		Context:      ctxMap,
		Async:        false,
	})
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"sub_run_id":  subRun.ID,
		"status":      subRun.Status,
		"step_count":  len(subRun.StepResults),
		"duration_ms": subRun.DurationMS,
	}
	return json.Marshal(result)
}
