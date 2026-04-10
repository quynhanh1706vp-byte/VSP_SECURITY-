package safe

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestGo_RunsFunction(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	Go(func() {
		defer wg.Done()
	})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	// OK
	case <-time.After(time.Second):
		t.Error("goroutine did not complete in time")
	}
}

func TestGo_RecoversPanic(t *testing.T) {
	// Should not crash the test
	Go(func() {
		panic("test panic — should be recovered")
	})
	time.Sleep(100 * time.Millisecond)
	// If we reach here, panic was recovered
}

func TestGoCtx_RunsWithContext(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)

	ctx := context.Background()
	GoCtx(ctx, func(c context.Context) {
		defer wg.Done()
		if c == nil {
			panic("context is nil")
		}
	})

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("goroutine did not complete")
	}
}

func TestGoCtx_RecoversPanic(t *testing.T) {
	GoCtx(context.Background(), func(ctx context.Context) {
		panic("ctx panic — should be recovered")
	})
	time.Sleep(100 * time.Millisecond)
}
