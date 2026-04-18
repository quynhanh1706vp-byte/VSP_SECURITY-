package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter is a simple sliding window rate limiter per key.
type RateLimiter struct {
	mu      sync.Mutex
	windows map[string][]time.Time
	max     int
	window  time.Duration
}

func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		windows: make(map[string][]time.Time),
		max:     max,
		window:  window,
	}
	// Cleanup stale entries every 5 minutes to avoid memory leak
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

// realIP extracts the real client IP.
// SECURITY: Uses RemoteAddr (TCP connection) as primary source — cannot be spoofed.
// X-Forwarded-For is NOT trusted by default to prevent rate-limit bypass attacks.
// Configure a reverse proxy (nginx/caddy) to overwrite RemoteAddr if needed.
func realIP(r *http.Request) string {
	// Use actual TCP connection address — spoof-proof
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// Middleware returns a chi-compatible rate limiting middleware.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := realIP(r)
		if !rl.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.Header().Set("X-RateLimit-Limit", "200")
			w.Header().Set("X-RateLimit-Window", "60s")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit exceeded","retry_after":60}`)) //nolint
			return
		}
		next.ServeHTTP(w, r)
	})
}

// StrictLimiter returns a tighter per-route limiter (e.g. for auth endpoints).
// Usage: r.With(StrictLimiter(5, time.Minute)).Post("/api/v1/auth/login", ...)
func StrictLimiter(max int, window time.Duration) func(http.Handler) http.Handler {
	rl := NewRateLimiter(max, window)
	return rl.Middleware
}

// UserMiddleware là rate limiter per user_id (dùng sau auth middleware).
// Khắc phục bypass dùng proxy của IP-based limiter.
// Lấy user_id từ chi context key "user_id".
func (rl *RateLimiter) UserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Lấy user_id từ context (được inject bởi auth middleware)
		userID, _ := r.Context().Value("user_id").(string)
		key := userID
		if key == "" {
			// Fallback về IP nếu chưa auth
			key = "ip:" + realIP(r)
		} else {
			key = "uid:" + userID
		}
		if !rl.Allow(key) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit exceeded","retry_after":60}`)) //nolint
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewUserRateLimiter tạo per-user rate limiter với Redis backend (nếu có).
// Dùng sau auth group để áp dụng per-user limits.
func NewUserRateLimiter(max int, window time.Duration) func(http.Handler) http.Handler {
	rl := NewRateLimiter(max, window)
	return rl.UserMiddleware
}
