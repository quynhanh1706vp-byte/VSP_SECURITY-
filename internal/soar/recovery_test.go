package soar

import (
	"context"
	"testing"
	"time"
)

type stubZombieStore struct{ count int }

func (s *stubZombieStore) MarkZombieRunsFailed(ctx context.Context, d time.Duration) (int, error) {
	return s.count, nil
}

func TestZombieRecovery_RunOnce(t *testing.T) {
	z := NewZombieRecovery(&stubZombieStore{count: 3}, time.Minute)
	n, err := z.RunOnce(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("got n=%d err=%v", n, err)
	}
}

func TestZombieRecovery_DefaultGrace(t *testing.T) {
	z := NewZombieRecovery(&stubZombieStore{}, 0)
	if z.grace != 10*time.Minute {
		t.Errorf("default grace = %v", z.grace)
	}
}

func TestZombieRecovery_StartLoopCancels(t *testing.T) {
	z := NewZombieRecovery(&stubZombieStore{}, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { z.StartLoop(ctx, 50*time.Millisecond); close(done) }()
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Error("loop didn't stop")
	}
}
