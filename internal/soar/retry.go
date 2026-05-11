package soar

import (
	"context"
	"math"
	"math/rand"
	"time"
)

// DefaultRetry returns a sensible default retry policy.
func DefaultRetry() *RetryPolicy {
	return &RetryPolicy{
		Max:         0,
		Backoff:     BackoffFixed,
		BaseMS:      1000,
		MaxMS:       30000,
		JitterRatio: 0.1,
	}
}

// computeDelay returns the delay for the Nth attempt (1-indexed).
//
//   - fixed:        BaseMS
//   - linear:       BaseMS * attempt
//   - exponential:  BaseMS * 2^(attempt-1)
//
// All capped at MaxMS, with optional jitter.
func computeDelay(p *RetryPolicy, attempt int) time.Duration {
	if p == nil || p.BaseMS <= 0 {
		return 0
	}
	if attempt < 1 {
		attempt = 1
	}
	var ms float64
	switch p.Backoff {
	case BackoffLinear:
		ms = float64(p.BaseMS) * float64(attempt)
	case BackoffExponential:
		ms = float64(p.BaseMS) * math.Pow(2, float64(attempt-1))
	default:
		ms = float64(p.BaseMS)
	}
	if p.MaxMS > 0 && ms > float64(p.MaxMS) {
		ms = float64(p.MaxMS)
	}
	// Apply jitter (additive, ±jitter_ratio * ms)
	if p.JitterRatio > 0 {
		j := (rand.Float64()*2 - 1) * p.JitterRatio * ms //#nosec G404 -- jitter only, not cryptographic
		ms += j
		if ms < 0 {
			ms = 0
		}
	}
	return time.Duration(ms) * time.Millisecond
}

// RetryFunc — callable that may fail.
type RetryFunc func(ctx context.Context, attempt int) error

// IsRetryable allows callers to mark errors as terminal (e.g. 4xx HTTP).
type IsRetryable func(err error) bool

// Retry executes fn with the given policy. Returns the last error if all
// attempts fail. attempt counter is 1-indexed.
//
// If ctx is cancelled mid-backoff, returns ctx.Err() immediately.
func Retry(ctx context.Context, p *RetryPolicy, isRetryable IsRetryable, fn RetryFunc) error {
	if p == nil {
		p = &RetryPolicy{Max: 0}
	}
	maxAttempts := p.Max + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fn(ctx, attempt)
		if err == nil {
			return nil
		}
		lastErr = err

		// Don't sleep after final attempt
		if attempt == maxAttempts {
			break
		}

		// Honor non-retryable errors (e.g. 4xx)
		if isRetryable != nil && !isRetryable(err) {
			break
		}

		delay := computeDelay(p, attempt)
		if delay <= 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return lastErr
}
