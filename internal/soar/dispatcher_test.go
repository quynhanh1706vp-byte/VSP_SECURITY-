package soar

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestDispatcher_RegisterDefault(t *testing.T) {
	d := NewDispatcher()
	d.RegisterDefault()
	for _, st := range []StepType{
		StepSetVar, StepCondition, StepWait, StepLoop, StepEnd,
		StepEnrich, StepBlock, StepRemediate,
	} {
		if !d.Has(st) {
			t.Errorf("missing executor for %s", st)
		}
	}
}

func TestDispatcher_DispatchUnregistered(t *testing.T) {
	d := NewDispatcher()
	_, _, err := d.Dispatch(context.Background(),
		&Node{ID: "n1", Type: StepHTTP},
		&ExecCtx{})
	if err == nil {
		t.Fatal("expected error for unregistered type")
	}
	var engErr *EngineError
	if !errors.As(err, &engErr) {
		t.Errorf("expected EngineError, got %T", err)
	}
}

type stubExec struct {
	called bool
	out    json.RawMessage
}

func (s *stubExec) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	s.called = true
	return s.out, "", nil
}

func TestDispatcher_Register(t *testing.T) {
	d := NewDispatcher()
	stub := &stubExec{out: json.RawMessage(`{"ok":true}`)}
	d.Register(StepHTTP, stub)
	out, _, err := d.Dispatch(context.Background(),
		&Node{ID: "n1", Type: StepHTTP},
		&ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	if !stub.called {
		t.Error("stub not called")
	}
	if string(out) != `{"ok":true}` {
		t.Errorf("got %s", string(out))
	}
}
