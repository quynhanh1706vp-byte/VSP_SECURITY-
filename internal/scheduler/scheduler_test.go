package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/vsp/platform/internal/store"
)

func TestNew(t *testing.T) {
	called := false
	enqueue := func(rid, tenantID, mode, profile, src, url string) {
		called = true
	}
	e := New(nil, enqueue)
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	_ = called
}

func TestListSchedules_Empty(t *testing.T) {
	e := New(nil, func(a,b,c,d,f,g string) {})
	scheds := e.ListSchedules(context.Background())
	if scheds == nil {
		t.Error("expected non-nil slice")
	}
	if len(scheds) != 0 {
		t.Errorf("expected 0 schedules, got %d", len(scheds))
	}
}

func TestTriggerNow(t *testing.T) {
	var triggered []string
	e := New(nil, func(rid, tenantID, mode, profile, src, url string) {
		triggered = append(triggered, rid)
	})

	s := store.StoreSchedule{
		ID:       "sched-1",
		TenantID: "tenant-1",
		Mode:     "SAST",
		Profile:  "FAST",
		Src:      "/code",
	}
	e.TriggerNow(context.Background(), s)

	// Give goroutine time to run
	time.Sleep(50 * time.Millisecond)
	if len(triggered) == 0 {
		t.Error("expected enqueue to be called")
	}
}

func TestStop_BeforeStart(t *testing.T) {
	// Should not panic
	e := New(nil, func(a,b,c,d,f,g string) {})
	e.Stop()
}
