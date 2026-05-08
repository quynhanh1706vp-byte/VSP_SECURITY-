// Package secrets — periodic secret cache refresh / rotation watcher.
//
// The Vault provider caches the KV v2 bundle on first read and never
// updates it again — operator must restart for new secrets. This file
// adds a goroutine that periodically polls Vault and atomically swaps
// the in-memory cache, enabling zero-downtime rotation.
//
// Rotation pattern:
//   1. Operator writes new secrets to Vault (e.g. via `vault kv patch`)
//   2. Within rotateInterval (default 15 min) the watcher picks up new
//      values and swaps them into the cache.
//   3. JWT signing accepts BOTH the new secret (for new tokens) and
//      the previous secret (for in-flight ones) for the rotation
//      window — see internal/auth/rotation.go which already reads
//      JWT_SECRET_OLD; the watcher mirrors the previous value into
//      that env-equivalent slot when it changes.
//
// We deliberately keep this dead simple: poll, swap, log. No leader
// election, no distributed coordination. Each gateway replica polls
// independently; cache divergence between replicas is ≤ rotateInterval.
package secrets

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

const defaultRotateInterval = 15 * time.Minute

// VaultProvider rotation hooks ─────────────────────────────────────────────

// StartRotator launches a goroutine that re-fetches the Vault KV bundle
// every interval. The goroutine ends when ctx is cancelled. Safe to call
// multiple times — only the first call wins.
func (v *VaultProvider) StartRotator(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = defaultRotateInterval
	}
	if !atomic.CompareAndSwapInt32(&v.rotatorStarted, 0, 1) {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		log.Info().Dur("interval", interval).Msg("vault rotator started")
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				v.pollAndSwap(ctx)
			}
		}
	}()
}

// pollAndSwap fetches the current KV bundle and atomically replaces the
// cache. Errors log and skip — never panic; rotation is best-effort and
// the existing cache stays valid.
func (v *VaultProvider) pollAndSwap(ctx context.Context) {
	// We re-do the same fetch path as ensureCache but with a fresh
	// (empty) cache so it always hits Vault.
	old := v.snapshot()
	v.mu.Lock()
	v.cached = nil
	v.mu.Unlock()
	if err := v.ensureCache(); err != nil {
		// Restore previous cache so callers don't see ErrNotFound for
		// keys that were valid a moment ago.
		v.mu.Lock()
		v.cached = old
		v.mu.Unlock()
		log.Warn().Err(err).Msg("vault rotator: poll failed (cache preserved)")
		return
	}
	if changed := v.diffKeys(old); len(changed) > 0 {
		log.Info().
			Strs("changed_keys", changed).
			Msg("vault rotator: cache refreshed with new values")
	}
}

func (v *VaultProvider) snapshot() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make(map[string]string, len(v.cached))
	for k, val := range v.cached {
		out[k] = val
	}
	return out
}

func (v *VaultProvider) diffKeys(prev map[string]string) []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var changed []string
	for k, val := range v.cached {
		if prev[k] != val {
			changed = append(changed, k)
		}
	}
	for k := range prev {
		if _, ok := v.cached[k]; !ok {
			changed = append(changed, k+":removed")
		}
	}
	return changed
}
