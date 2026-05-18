package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// PgxQuerier is the minimum interface needed for cache I/O.
// Compatible with both pgx.Conn and pgxpool.Pool.
type PgxQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) PgxRow
	Exec(ctx context.Context, sql string, args ...interface{}) (interface{}, error)
}

// PgxRow is the minimum interface for a single row scan.
type PgxRow interface {
	Scan(dest ...interface{}) error
}

// CacheKey computes a stable hash for a fix request.
// Same rule + same file + same vulnerable code → same key.
func CacheKey(req FixRequest) string {
	h := sha256.New()
	h.Write([]byte(req.RuleID))
	h.Write([]byte("|"))
	h.Write([]byte(req.FilePath))
	h.Write([]byte("|"))
	inner := sha256.Sum256([]byte(req.VulnerableCode))
	h.Write(inner[:])
	return hex.EncodeToString(h.Sum(nil))
}

// CacheGet returns a cached fix or nil if missing/expired.
// Errors are returned but callers should treat as cache miss (best-effort).
func CacheGet(ctx context.Context, db PgxQuerier, key string) (*FixResponse, error) {
	var r FixResponse
	var latency int
	row := db.QueryRow(ctx,
		`SELECT suggested_code, rationale, confidence, breaking_change,
		        provider, model, COALESCE(latency_ms, 0)
		   FROM autofix_cache
		  WHERE cache_key = $1 AND expires_at > NOW()
		  LIMIT 1`,
		key,
	)
	if err := row.Scan(&r.SuggestedCode, &r.Rationale, &r.Confidence,
		&r.BreakingChange, &r.Provider, &r.Model, &latency); err != nil {
		return nil, err
	}
	r.LatencyMs = int64(latency)
	return &r, nil
}

// CacheSet stores a fix response. TTL defaults to 30 days.
func CacheSet(ctx context.Context, db PgxQuerier, key string, findingID string, resp FixResponse, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	expires := time.Now().Add(ttl)
	_, err := db.Exec(ctx,
		`INSERT INTO autofix_cache (cache_key, finding_id, provider, model,
		    suggested_code, rationale, confidence, breaking_change,
		    tokens_used, latency_ms, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (cache_key) DO UPDATE
		   SET suggested_code  = EXCLUDED.suggested_code,
		       rationale       = EXCLUDED.rationale,
		       confidence      = EXCLUDED.confidence,
		       breaking_change = EXCLUDED.breaking_change,
		       tokens_used     = EXCLUDED.tokens_used,
		       latency_ms      = EXCLUDED.latency_ms,
		       expires_at      = EXCLUDED.expires_at`,
		key, nilIfEmpty(findingID), resp.Provider, resp.Model,
		resp.SuggestedCode, resp.Rationale, resp.Confidence, resp.BreakingChange,
		resp.TokensUsed, resp.LatencyMs, expires,
	)
	if err != nil {
		return fmt.Errorf("cache set: %w", err)
	}
	return nil
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
