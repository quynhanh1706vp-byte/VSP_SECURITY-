package middleware

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter is a simple sliding window rate limiter per IP.
type RateLimiter struct {
	mu       sync.Mutex
	windows  map[string][]time.Time
	max      int
	window   time.Duration
}

func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		windows: make(map[string][]time.Time),
		max:     max,
		window:  window,
	}
	// Cleanup stale entries mỗi 5 phút để tránh memory leak
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			rl.mu.Lock()
			cutoff := time.Now().Add(-window)
			for k, times := range rl.windows {
				valid := times[:0]
				for _, t := range times {
					if t.After(cutoff) {
						valid = append(valid, t)
					}
				}
				if len(valid) == 0 {
					delete(rl.windows, k)
				} else {
					rl.windows[k] = valid
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Prune old entries
	times := rl.windows[key]
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.max {
		rl.windows[key] = valid
		return false
	}

	rl.windows[key] = append(valid, now)
	return true
}

// Middleware returns a chi-compatible rate limiting middleware.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if !rl.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded","retry_after":60}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
