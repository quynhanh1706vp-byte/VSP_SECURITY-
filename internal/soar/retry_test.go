package soar

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetry_SuccessFirstTry(t *testing.T) {
	calls := 0
	err := Retry(context.Background(),
		&RetryPolicy{Max: 3, BaseMS: 1, Backoff: BackoffFixed},
		nil,
		func(ctx context.Context, attempt int) error {
			calls++
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestRetry_SuccessOnThirdTry(t *testing.T) {
	calls := 0
	err := Retry(context.Background(),
		&RetryPolicy{Max: 5, BaseMS: 1, Backoff: BackoffFixed},
		nil,
		func(ctx context.Context, attempt int) error {
			calls++
			if attempt < 3 {
				return errors.New("transient")
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRetry_AllFail(t *testing.T) {
	calls := 0
	err := Retry(context.Background(),
		&RetryPolicy{Max: 2, BaseMS: 1, Backoff: BackoffFixed},
		nil,
		func(ctx context.Context, attempt int) error {
			calls++
			return errors.New("nope")
		})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 3 { // 1 initial + 2 retries
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRetry_NonRetryableTerminates(t *testing.T) {
	calls := 0
	terminal := errors.New("terminal")
	err := Retry(context.Background(),
		&RetryPolicy{Max: 5, BaseMS: 1, Backoff: BackoffFixed},
		func(e error) bool { return !errors.Is(e, terminal) },
		func(ctx context.Context, attempt int) error {
			calls++
			return terminal
		})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("expected 1 call (no retry on terminal), got %d", calls)
	}
}

func TestRetry_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	err := Retry(ctx,
		&RetryPolicy{Max: 100, BaseMS: 50, Backoff: BackoffFixed},
		nil,
		func(ctx context.Context, attempt int) error {
			calls++
			return errors.New("keep retrying")
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls > 5 {
		t.Fatalf("ran too many times before cancel: %d", calls)
	}
}

func TestComputeDelay_Strategies(t *testing.T) {
	tests := []struct {
		name    string
		policy  *RetryPolicy
		attempt int
		minMS   int64
		maxMS   int64
	}{
		{"fixed", &RetryPolicy{BaseMS: 100, Backoff: BackoffFixed}, 1, 100, 100},
		{"fixed-attempt-3", &RetryPolicy{BaseMS: 100, Backoff: BackoffFixed}, 3, 100, 100},
		{"linear-1", &RetryPolicy{BaseMS: 100, Backoff: BackoffLinear}, 1, 100, 100},
		{"linear-3", &RetryPolicy{BaseMS: 100, Backoff: BackoffLinear}, 3, 300, 300},
		{"exp-1", &RetryPolicy{BaseMS: 100, Backoff: BackoffExponential}, 1, 100, 100},
		{"exp-3", &RetryPolicy{BaseMS: 100, Backoff: BackoffExponential}, 3, 400, 400},
		{"exp-capped", &RetryPolicy{BaseMS: 100, MaxMS: 250, Backoff: BackoffExponential}, 5, 250, 250},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := computeDelay(tt.policy, tt.attempt).Milliseconds()
			if d < tt.minMS || d > tt.maxMS {
				t.Errorf("got %d ms, want [%d, %d]", d, tt.minMS, tt.maxMS)
			}
		})
	}
}

func TestComputeDelay_JitterAddsRandomness(t *testing.T) {
	p := &RetryPolicy{BaseMS: 1000, Backoff: BackoffFixed, JitterRatio: 0.5}
	seen := make(map[int64]bool)
	for i := 0; i < 20; i++ {
		seen[computeDelay(p, 1).Milliseconds()] = true
	}
	if len(seen) < 5 {
		t.Errorf("jitter not random enough: %d distinct values in 20 trials", len(seen))
	}
}
