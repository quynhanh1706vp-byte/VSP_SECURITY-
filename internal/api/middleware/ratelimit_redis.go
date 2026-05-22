package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisRateLimiter implements sliding window rate limiting backed by Redis.
// Falls back to in-memory RateLimiter when Redis is unavailable.
// Uses INCR + EXPIRE — atomic per Redis single-threaded model, survives
// gateway restarts and works across multiple gateway instances.
type RedisRateLimiter struct {
	rdb      *redis.Client
	max      int
	window   time.Duration
	fallback *RateLimiter
}

// NewRedisRateLimiter creates a Redis-backed rate limiter.
// If rdb is nil or unreachable, falls back to in-memory.
func NewRedisRateLimiter(rdb *redis.Client, max int, window time.Duration) *RedisRateLimiter {
	return &RedisRateLimiter{
		rdb:      rdb,
		max:      max,
		window:   window,
		fallback: NewRateLimiter(max, window),
	}
}

// Allow checks and increments the rate limit counter for key.
// Returns true if the request is allowed.
func (rl *RedisRateLimiter) Allow(ctx context.Context, key string) bool {
	if rl.rdb == nil {
		return rl.fallback.Allow(key)
	}

	// Use a short context so Redis hiccup doesn't block the request.
	rCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	redisKey := fmt.Sprintf("vsp:rl:%s", key)

	pipe := rl.rdb.Pipeline()
	incr := pipe.Incr(rCtx, redisKey)
	pipe.Expire(rCtx, redisKey, rl.window)
	if _, err := pipe.Exec(rCtx); err != nil {
		// Redis unavailable — fail open with in-memory fallback.
		return rl.fallback.Allow(key)
	}

	return incr.Val() <= int64(rl.max)
}

// Middleware returns a chi-compatible middleware using Redis rate limiting.
func (rl *RedisRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := "ip:" + realIP(r)
		if !rl.Allow(r.Context(), key) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", rl.window.Seconds()))
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.max))
			w.Header().Set("X-RateLimit-Window", rl.window.String())
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit exceeded","retry_after":60}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// UserMiddleware rate-limits per user ID (after auth), falling back to IP.
func (rl *RedisRateLimiter) UserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, _ := r.Context().Value("user_id").(string)
		key := "uid:" + userID
		if userID == "" {
			key = "ip:" + realIP(r)
		}
		if !rl.Allow(r.Context(), key) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", rl.window.Seconds()))
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit exceeded","retry_after":60}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// StrictLimiterRedis returns a Redis-backed strict limiter for auth endpoints.
// Drop-in replacement for StrictLimiter — same signature.
func StrictLimiterRedis(rdb *redis.Client, max int, window time.Duration) func(http.Handler) http.Handler {
	rl := NewRedisRateLimiter(rdb, max, window)
	return rl.Middleware
}
