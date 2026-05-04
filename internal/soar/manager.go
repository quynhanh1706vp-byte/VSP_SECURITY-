package soar

import (
	"context"
	"fmt"
)

// Manager — top-level orchestration for handler layer.
//
// Handler/HTTP layer should use Manager methods, not Engine directly.
// Manager handles: loading playbook, status checks, default options.
type Manager struct {
	engine *Engine
	store  EngineStore
}

// NewManager wraps an engine + store.
func NewManager(engine *Engine, store EngineStore) *Manager {
	return &Manager{engine: engine, store: store}
}

// ExecuteByID — load playbook by ID, then execute.
// Returns immediately if opts.Async, else blocks until done.
func (m *Manager) ExecuteByID(ctx context.Context, tenantID, playbookID string, opts ExecuteOptions) (*Run, error) {
	pb, err := m.store.GetPlaybook(ctx, tenantID, playbookID)
	if err != nil {
		return nil, fmt.Errorf("manager: load: %w", err)
	}
	if pb.Status == "disabled" || pb.Status == "archived" {
		if !opts.IsTest {
			return nil, fmt.Errorf("manager: playbook %s is %s", playbookID, pb.Status)
		}
	}
	return m.engine.Execute(ctx, pb, opts)
}

// CancelRun aborts a running run.
func (m *Manager) CancelRun(runID string) error {
	return m.engine.Cancel(runID)
}
