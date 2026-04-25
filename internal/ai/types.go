package ai

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// AdviseRequest is the canonical input to the Advisor — identifies a single
// failing control + finding pair on which advice is requested.
type AdviseRequest struct {
	TenantID       string   `json:"tenant_id,omitempty"`
	Framework      string   `json:"framework"`
	ControlID      string   `json:"control_id"`
	FindingSummary string   `json:"finding_summary"`
	Evidence       []string `json:"evidence,omitempty"`
}

// EffortHours estimates the engineer-time required to complete a remediation,
// broken down by skill level.
type EffortHours struct {
	Junior int `json:"junior"`
	Mid    int `json:"mid"`
	Senior int `json:"senior"`
}

// AdviseResponse is the four-part remediation output. Field names match
// the JSON contract the LLM is asked to produce so client code is
// indifferent to whether the response came from Claude or local rules.
type AdviseResponse struct {
	Remediation string      `json:"remediation"`
	EffortHours EffortHours `json:"effort_hours"`
	Evidence    string      `json:"evidence"`
	References  []string    `json:"references"`
	RiskAccept  string      `json:"risk_acceptance_language,omitempty"`
	Source      string      `json:"source"` // "claude" or "local"
	Cached      bool        `json:"cached,omitempty"`
	CacheID     int64       `json:"cache_id,omitempty"`
}

// CacheKey produces a stable hash for a (framework, control, finding) tuple
// used for deduplication.
func (r AdviseRequest) CacheKey() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s", r.Framework, r.ControlID, r.FindingSummary)
	return hex.EncodeToString(h.Sum(nil))
}

// CacheLookup returns a previously-stored response if one exists for the
// same cache key. It also bumps last_used_at and use_count.
func CacheLookup(ctx context.Context, db *sql.DB, key string) (*AdviseResponse, int64, error) {
	var (
		id        int64
		respJSON  []byte
		mode      string
	)
	err := db.QueryRowContext(ctx, `
		SELECT id, response_json, mode FROM ai_advisor_cache WHERE cache_key = $1
	`, key).Scan(&id, &respJSON, &mode)
	if err == sql.ErrNoRows {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}

	var resp AdviseResponse
	if err := json.Unmarshal(respJSON, &resp); err != nil {
		return nil, 0, err
	}
	resp.Source = mode
	resp.Cached = true
	resp.CacheID = id

	// Bump usage counter; ignore error (best-effort).
	_, _ = db.ExecContext(ctx, `
		UPDATE ai_advisor_cache SET last_used_at = $1, use_count = use_count + 1
		WHERE id = $2
	`, time.Now(), id)

	return &resp, id, nil
}

// CacheStore writes a fresh response to the cache.
func CacheStore(ctx context.Context, db *sql.DB, req AdviseRequest, resp AdviseResponse,
	tokensIn, tokensOut int, model string) (int64, error) {
	respJSON, err := json.Marshal(resp)
	if err != nil {
		return 0, err
	}

	var id int64
	err = db.QueryRowContext(ctx, `
		INSERT INTO ai_advisor_cache
		  (cache_key, framework, control_id, finding_summary,
		   response_json, mode, model, tokens_in, tokens_out)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (cache_key) DO UPDATE
		SET last_used_at = now(), use_count = ai_advisor_cache.use_count + 1
		RETURNING id
	`, req.CacheKey(), req.Framework, req.ControlID, req.FindingSummary,
		respJSON, resp.Source, nullStr(model), tokensIn, tokensOut).Scan(&id)
	return id, err
}

// CacheStats summarizes cache effectiveness for the platform.
type CacheStats struct {
	TotalEntries int   `json:"total_entries"`
	TotalUses    int64 `json:"total_uses"`
	ClaudeMode   int   `json:"claude_count"`
	LocalMode    int   `json:"local_count"`
	TokensSaved  int64 `json:"tokens_saved_estimate"`
}

func GetCacheStats(ctx context.Context, db *sql.DB) (CacheStats, error) {
	var s CacheStats
	err := db.QueryRowContext(ctx, `
		SELECT
		  COUNT(*),
		  COALESCE(SUM(use_count), 0),
		  COALESCE(SUM(CASE WHEN mode = 'claude' THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM(CASE WHEN mode = 'local'  THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM((use_count - 1) * COALESCE(tokens_out, 0)), 0)
		FROM ai_advisor_cache
	`).Scan(&s.TotalEntries, &s.TotalUses, &s.ClaudeMode, &s.LocalMode, &s.TokensSaved)
	return s, err
}

// SubmitFeedback records a user-marked rating on a cached suggestion.
func SubmitFeedback(ctx context.Context, db *sql.DB, cacheID int64,
	tenantID, userEmail, rating, notes string) error {
	if rating != "helpful" && rating != "not_helpful" && rating != "partially" {
		return fmt.Errorf("invalid rating: %s", rating)
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO ai_advisor_feedback
		  (cache_id, tenant_id, user_email, rating, notes)
		VALUES ($1, $2, $3, $4, $5)
	`, cacheID, tenantID, nullStr(userEmail), rating, nullStr(notes))
	return err
}

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
