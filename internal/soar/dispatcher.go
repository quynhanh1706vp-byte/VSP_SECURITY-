package soar

import (
	"context"
	"encoding/json"
	"fmt"
)

// Dispatcher routes a node to its appropriate StepExecutor by type.
//
// Construction: pass concrete executors via With* methods. Engine creates
// dispatcher once and reuses across runs. This pattern allows mocking
// I/O steps in tests by swapping in fake executors.
type Dispatcher struct {
	executors map[StepType]StepExecutor
}

// NewDispatcher creates an empty dispatcher. Register executors before use.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{executors: make(map[StepType]StepExecutor)}
}

// Register adds a step type → executor binding. Overwrites any existing.
func (d *Dispatcher) Register(t StepType, exec StepExecutor) {
	d.executors[t] = exec
}

// RegisterDefault populates the dispatcher with built-in basic + legacy executors.
// I/O-heavy steps (http, notify, ticket, script, approval, sub_playbook, fork, join)
// must be registered separately by caller because they need external dependencies
// (HTTPDoer, Sandbox, Vault, etc.).
func (d *Dispatcher) RegisterDefault() {
	d.Register(StepSetVar, &setVarExecutor{})
	d.Register(StepCondition, &conditionExecutor{})
	d.Register(StepWait, &waitExecutor{})
	d.Register(StepLoop, &loopExecutor{})
	d.Register(StepEnd, &endExecutor{})

	// Legacy steps (always registered — DB-stored playbooks need these)
	d.Register(StepEnrich, &legacyEnrichExecutor{})
	d.Register(StepBlock, &legacyBlockExecutor{})
	d.Register(StepRemediate, &legacyRemediateExecutor{})
}

// Dispatch executes node via the registered executor.
//
// A panicking executor must NOT take down the SOAR worker goroutine —
// the engine is shared across all tenants and a single broken playbook
// step would otherwise stall every run. We wrap exec.Run in a recover
// so the panic is converted to an EngineError; the engine then marks
// the node as failed and continues with the playbook's error-handling
// edges (or halts the run, but not the worker).
func (d *Dispatcher) Dispatch(ctx context.Context, node *Node, ec *ExecCtx) (out json.RawMessage, next string, err error) {
	exec, ok := d.executors[node.Type]
	if !ok {
		return nil, "", &EngineError{
			NodeID:  node.ID,
			Step:    node.Type,
			Wrapped: fmt.Errorf("no executor registered for step type %q", node.Type),
		}
	}
	defer func() {
		if r := recover(); r != nil {
			err = &EngineError{
				NodeID:  node.ID,
				Step:    node.Type,
				Wrapped: fmt.Errorf("executor panic: %v", r),
			}
			out = nil
			next = ""
		}
	}()
	return exec.Run(ctx, node, ec)
}

// Has reports whether a step type has a registered executor.
func (d *Dispatcher) Has(t StepType) bool {
	_, ok := d.executors[t]
	return ok
}
