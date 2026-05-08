// Package auth — login lockout & timing-attack defenses.
//
// Three layers, designed to fail-closed independently:
//
//   1. Per-account lockout (existing in users.failed_logins)
//      Hard limit: 5 fails → 15-min lock. Already enforced by the auth
//      handler.
//
//   2. Per-IP sliding window (this file)
//      Defends against credential-stuffing: attacker iterates usernames,
//      each pass uses one user's quota only once. Tracks fails per IP
//      across a 10-min sliding window; >= 20 fails locks the IP for 15
//      min regardless of which username it tried. In-memory; Redis-back
//      for multi-replica is a future step (see PoolBeforeAcquire pattern
//      in store/rls.go for the migration path).
//
//   3. Constant-time response (this file)
//      DummyHash + matching bcrypt cost lets the handler ALWAYS run a
//      compare even when the user doesn't exist. Eliminates the timing
//      side-channel that previously let an attacker enumerate valid
//      emails (~50ms vs <1ms gap on production hardware).
package auth

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ── per-IP sliding window ──────────────────────────────────────────────────

const (
	ipWindow      = 10 * time.Minute
	ipFailLimit   = 20
	ipLockoutTime = 15 * time.Minute
)

type ipBucket struct {
	fails    []time.Time // ring of timestamps; trimmed on insert
	lockedAt time.Time
}

type IPLockout struct {
	mu      sync.Mutex
	buckets map[string]*ipBucket
}

func NewIPLockout() *IPLockout {
	return &IPLockout{buckets: make(map[string]*ipBucket)}
}

// IsLocked returns true if the IP is currently in lockout.
func (l *IPLockout) IsLocked(ip string) bool {
	if ip == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		return false
	}
	if !b.lockedAt.IsZero() && time.Since(b.lockedAt) < ipLockoutTime {
		return true
	}
	return false
}

// RecordFail bumps the IP's fail counter and locks the IP if the
// threshold is reached. Returns true when the IP just became locked
// on this call (caller can audit).
func (l *IPLockout) RecordFail(ip string) (newlyLocked bool, totalInWindow int) {
	if ip == "" {
		return false, 0
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		b = &ipBucket{}
		l.buckets[ip] = b
	}
	// Trim entries outside the window.
	cutoff := now.Add(-ipWindow)
	trimmed := b.fails[:0]
	for _, t := range b.fails {
		if t.After(cutoff) {
			trimmed = append(trimmed, t)
		}
	}
	b.fails = append(trimmed, now)
	if len(b.fails) >= ipFailLimit && b.lockedAt.IsZero() {
		b.lockedAt = now
		return true, len(b.fails)
	}
	return false, len(b.fails)
}

// Clear is called on a successful login; resets the bucket.
func (l *IPLockout) Clear(ip string) {
	if ip == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, ip)
}

// ClientIP extracts the best-effort source IP. Honours X-Forwarded-For
// when running behind a trusted reverse proxy (chi.RealIP middleware
// already populates RemoteAddr from XFF, so we just split off the port).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ── constant-time response defenses ────────────────────────────────────────

// dummyBcryptHash is a precomputed hash of "vsp-nonexistent-user-marker"
// at bcrypt cost 12 (matching DefaultCost). The handler runs a bcrypt
// compare against this when the looked-up user is nil so the wall-clock
// time of the failure path matches the success path.
//
// Generated once at package init; not persisted because there is no
// secret to protect — the goal is timing parity, not authentication.
var dummyBcryptHash = mustGenerateDummyHash()

func mustGenerateDummyHash() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("vsp-nonexistent-user-marker"), bcrypt.DefaultCost)
	if err != nil {
		// Should never happen — bcrypt.GenerateFromPassword only errors on
		// invalid cost. We fall back to a placeholder so the package still
		// loads; the timing side-channel is back but the binary boots.
		return []byte("$2a$12$dummyhashthatcannotmatchanything")
	}
	return h
}

// CompareDummyPassword runs a bcrypt compare against the precomputed
// dummy hash so the failed-lookup path takes the same wall-clock time
// as a real-but-wrong password compare. Always returns an error.
func CompareDummyPassword(attempted string) error {
	return bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(attempted))
}

// ── exponential backoff ────────────────────────────────────────────────────

// BackoffSleep blocks the request for an exponentially increasing
// duration based on the recent fail count. After 5 fails the sleep
// caps at 8 s — this slows online password guessing without making
// successful logins suffer (success resets the count).
//
// Caller passes the user's current failed_logins count.
func BackoffSleep(failedCount int) {
	if failedCount <= 0 {
		return
	}
	d := time.Second
	for i := 1; i < failedCount && i < 4; i++ {
		d *= 2
	}
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	time.Sleep(d)
}
