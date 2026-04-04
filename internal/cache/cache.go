package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// Client wraps redis cho API response caching.
type Client struct {
	rdb *redis.Client
}

// New tạo cache client. Nếu Redis không available, trả về no-op client.
func New(addr, password string) *Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       1, // DB 1 để tách khỏi asynq (DB 0)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Warn().Err(err).Msg("cache: Redis not available — caching disabled")
		return &Client{rdb: nil}
	}
	log.Info().Str("addr", addr).Msg("cache: Redis connected ✓")
	return &Client{rdb: rdb}
}

// Get lấy cached value. Trả về nil nếu miss hoặc Redis unavailable.
func (c *Client) Get(ctx context.Context, key string) []byte {
	if c.rdb == nil {
		return nil
	}
	val, err := c.rdb.Get(ctx, key).Bytes()
	if err != nil {
		return nil
	}
	return val
}

// Set lưu value với TTL.
func (c *Client) Set(ctx context.Context, key string, value []byte, ttl time.Duration) {
	if c.rdb == nil {
		return
	}
	if err := c.rdb.Set(ctx, key, value, ttl).Err(); err != nil {
		log.Warn().Err(err).Str("key", key).Msg("cache: set failed")
	}
}

// SetJSON marshal và cache object.
func (c *Client) SetJSON(ctx context.Context, key string, v any, ttl time.Duration) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	c.Set(ctx, key, b, ttl)
}

// Invalidate xóa cache key (dùng khi có data thay đổi).
func (c *Client) Invalidate(ctx context.Context, pattern string) {
	if c.rdb == nil {
		return
	}
	keys, err := c.rdb.Keys(ctx, pattern).Result()
	if err != nil || len(keys) == 0 {
		return
	}
	c.rdb.Del(ctx, keys...)
}

// HTTPMiddleware là chi middleware cache HTTP responses.
// TTL ngắn (5-30s) cho các endpoint read-heavy.
//
// Dùng trong main.go:
//
//	ca := cache.New(redisAddr, redisPass)
//	r.With(ca.Middleware("posture", 10*time.Second)).Get("/api/v1/vsp/posture/latest", ...)
func (c *Client) Middleware(name string, ttl time.Duration) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Chỉ cache GET requests
			if r.Method != "GET" || c.rdb == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Cache key = name + query string (tenant-aware qua JWT được inject context)
			key := "vsp:api:" + name + ":" + r.URL.RawQuery

			// Cache hit
			if cached := c.Get(r.Context(), key); cached != nil {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Cache", "HIT")
				w.Write(cached)
				return
			}

			// Cache miss — capture response
			rw := &responseCapture{ResponseWriter: w, body: &bytes.Buffer{}}
			next.ServeHTTP(rw, r)

			// Chỉ cache 200 responses
			if rw.status == 200 || rw.status == 0 {
				c.Set(r.Context(), key, rw.body.Bytes(), ttl)
				w.Header().Set("X-Cache", "MISS")
			}
		})
	}
}

// responseCapture captures HTTP response body.
type responseCapture struct {
	http.ResponseWriter
	body   *bytes.Buffer
	status int
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.status = code
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	rc.body.Write(b)
	return rc.ResponseWriter.Write(b)
}
