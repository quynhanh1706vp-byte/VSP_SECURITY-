package soar

import (
	"context"
	"time"
)

// ZombieRecovery cleans up runs left in 'running' status after a crash.
//
// On gateway restart, any run that was mid-execution will have status='running'
// in DB but no goroutine driving it. This is a zombie. We mark them as 'failed'
// with a clear error message after a grace period (default 10 min — should be
// > the typical max run duration to avoid killing actually-running runs).
type ZombieRecovery struct {
	store ZombieStore
	grace time.Duration
}

// ZombieStore — minimal interface for recovery. *store.DB satisfies via
// existing pool methods.
type ZombieStore interface {
	MarkZombieRunsFailed(ctx context.Context, olderThan time.Duration) (count int, err error)
}

// NewZombieRecovery — pass *store.DB or any compatible implementation.
// grace=0 uses sensible default (10min, > MaxRunDurationSec).
func NewZombieRecovery(s ZombieStore, grace time.Duration) *ZombieRecovery {
	if grace <= 0 {
		grace = 10 * time.Minute
	}
	return &ZombieRecovery{store: s, grace: grace}
}

// RunOnce performs one cleanup pass. Returns number of zombie runs marked failed.
func (z *ZombieRecovery) RunOnce(ctx context.Context) (int, error) {
	return z.store.MarkZombieRunsFailed(ctx, z.grace)
}

// StartLoop runs cleanup every `interval`. Stops on ctx cancel.
// Best run as goroutine via safe.GoCtx pattern.
func (z *ZombieRecovery) StartLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	// Initial cleanup on startup
	_, _ = z.RunOnce(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = z.RunOnce(ctx)
		}
	}
}
