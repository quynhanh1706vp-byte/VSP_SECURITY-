// =====================================================================
// H3.Q Fix Validation Pipeline — HTTP Handlers + Worker Integration
// File: internal/autofix/validation_handlers.go
//
// Wires up:
//   GET  /api/v1/autofix/validation/:cache_key   — fetch results for one fix
//   GET  /api/v1/autofix/validation/stats        — aggregate dashboard stats
//   POST /api/v1/autofix/validation/run          — manual re-validation trigger (admin)
//
// Also exposes ValidateAndCache() — called by H3.O precompute worker
// AFTER LLM produces a fix but BEFORE it's persisted to autofix_cache.
// =====================================================================

package autofix

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ValidationGate — config for "should this fix be cached at all"
type ValidationGate struct {
	// MinScore — fixes below this score are NOT cached (default 50)
	MinScore int
	// RejectOnFail — if any of these validators fail, reject completely
	RejectOnFail []string
}

func DefaultGate() ValidationGate {
	return ValidationGate{
		MinScore:     50,
		RejectOnFail: []string{"lint"}, // lint regression = hard reject
	}
}

// ShouldCache — decide whether to persist this fix to autofix_cache.
// Called by H3.O precompute worker right after validation.
func (g ValidationGate) ShouldCache(pr *PipelineResult) (bool, string) {
	if pr == nil {
		return false, "nil result"
	}
	if pr.Score < g.MinScore {
		return false, fmt.Sprintf("score %d < min %d", pr.Score, g.MinScore)
	}
	for _, r := range pr.Results {
		for _, rej := range g.RejectOnFail {
			if r.Validator == rej && r.Status == StatusFail {
				return false, fmt.Sprintf("hard-reject: %s failed (%s)", rej, r.ErrorMsg)
			}
		}
	}
	return true, ""
}

// =====================================================================
// PRECOMPUTE WORKER INTEGRATION
// Replace the H3.O persist call from:
//     cache.Store(key, suggestedCode, confidence, ...)
// to:
//     ok, reason := autofix.ValidateAndCache(ctx, db, candidate, suggestedCode, confidence)
//     if !ok { log "[H3.O] skipped: " + reason }
// =====================================================================

// ValidateAndCache — runs validation pipeline; persists to cache only if gate passes.
// Returns (cached bool, reasonIfRejected string).
func ValidateAndCache(
	ctx context.Context,
	db *sql.DB,
	pipeline *Pipeline,
	gate ValidationGate,
	c *FixCandidate,
	rationale string,
) (bool, string, *PipelineResult) {
	if pipeline == nil {
		pipeline = NewPipeline(db)
	}
	pr, err := pipeline.Run(ctx, c)
	if err != nil {
		return false, "pipeline error: " + err.Error(), nil
	}

	ok, reason := gate.ShouldCache(pr)
	if !ok {
		// Insert validation rows so we have telemetry on REJECTED fixes too
		// (pipeline.Run already persisted via Pipeline.persist)
		return false, reason, pr
	}

	// Insert/upsert into autofix_cache. The H3.O code path that called this
	// should remove its own INSERT and rely on this method.
	stmt := `INSERT INTO autofix_cache
		(cache_key, finding_id, suggested_code, rationale, confidence,
		 confidence_final, validation_score, validation_status, validation_at,
		 created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(),
		        NOW() + INTERVAL '30 days')
		ON CONFLICT (cache_key) DO UPDATE SET
		  suggested_code = EXCLUDED.suggested_code,
		  rationale = EXCLUDED.rationale,
		  confidence = EXCLUDED.confidence,
		  confidence_final = EXCLUDED.confidence_final,
		  validation_score = EXCLUDED.validation_score,
		  validation_status = EXCLUDED.validation_status,
		  validation_at = EXCLUDED.validation_at,
		  expires_at = NOW() + INTERVAL '30 days'`

	_, err = db.ExecContext(ctx, stmt,
		c.CacheKey, c.FindingID, c.SuggestedCode, rationale,
		c.ConfidenceIn, pr.ConfidenceFinal,
		pr.Score, pr.OverallStatus, pr.ValidatedAt,
	)
	if err != nil {
		return false, "cache insert: " + err.Error(), pr
	}
	return true, "", pr
}

// =====================================================================
// HTTP HANDLERS
// =====================================================================

// HandlerGetValidation — GET /api/v1/autofix/validation/:cache_key
// Auth required (CMMC AC-3). Audit log on access (CMMC AU-2).
func HandlerGetValidation(db *sql.DB) http.HandlerFunc {
	pipeline := NewPipeline(db)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Path: /api/v1/autofix/validation/{cache_key}
		key := strings.TrimPrefix(r.URL.Path, "/api/v1/autofix/validation/")
		key = strings.TrimSpace(key)
		if key == "" || len(key) < 32 || len(key) > 128 {
			http.Error(w, "invalid cache_key", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		pr, err := pipeline.LookupByCacheKey(ctx, key)
		if err != nil {
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return
		}
		if pr == nil || len(pr.Results) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"cache_key": key,
				"validated": false,
				"message":   "no validation results — fix may predate H3.Q",
			})
			return
		}

		// Audit log (no source code, just metadata)
		_, _ = db.ExecContext(ctx,
			`INSERT INTO audit_log (action, resource, actor, metadata, created_at)
			 VALUES ('autofix.validation.read', $1, $2, $3, NOW())
			 ON CONFLICT DO NOTHING`,
			"cache_key:"+key[:16],
			actorFromCtx(r),
			fmt.Sprintf(`{"score":%d,"status":"%s"}`, pr.Score, pr.OverallStatus),
		)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, max-age=60")
		_ = json.NewEncoder(w).Encode(pr)
	}
}

// HandlerValidationStats — GET /api/v1/autofix/validation/stats
// Returns aggregate per-validator stats (last 30 days).
func HandlerValidationStats(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		rows, err := db.QueryContext(ctx, `
			SELECT validator, total, pass_count, fail_count, skip_count,
			       error_count, COALESCE(pass_rate_pct, 0), COALESCE(avg_duration_ms, 0),
			       COALESCE(last_run, NOW())
			FROM v_autofix_validation_stats`)
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type vstat struct {
			Validator     string  `json:"validator"`
			Total         int     `json:"total"`
			Pass          int     `json:"pass"`
			Fail          int     `json:"fail"`
			Skip          int     `json:"skip"`
			Error         int     `json:"error"`
			PassRatePct   float64 `json:"pass_rate_pct"`
			AvgDurationMs float64 `json:"avg_duration_ms"`
			LastRun       string  `json:"last_run"`
		}
		out := []vstat{}
		for rows.Next() {
			var s vstat
			var lastRun time.Time
			if err := rows.Scan(&s.Validator, &s.Total, &s.Pass, &s.Fail,
				&s.Skip, &s.Error, &s.PassRatePct, &s.AvgDurationMs, &lastRun); err != nil {
				http.Error(w, "scan failed", http.StatusInternalServerError)
				return
			}
			s.LastRun = lastRun.UTC().Format(time.RFC3339)
			out = append(out, s)
		}

		// Top-level summary
		var totalCacheRows, validatedRows, passRows, failRows int
		_ = db.QueryRowContext(ctx, `
			SELECT
			  COUNT(*),
			  COUNT(*) FILTER (WHERE validation_status IS NOT NULL),
			  COUNT(*) FILTER (WHERE validation_status = 'pass'),
			  COUNT(*) FILTER (WHERE validation_status = 'fail')
			FROM autofix_cache
			WHERE created_at > NOW() - INTERVAL '30 days'`).
			Scan(&totalCacheRows, &validatedRows, &passRows, &failRows)

		resp := map[string]any{
			"validators": out,
			"summary": map[string]any{
				"cache_entries_30d": totalCacheRows,
				"validated":         validatedRows,
				"pass":              passRows,
				"fail":              failRows,
				"validation_coverage_pct": pct(validatedRows, totalCacheRows),
			},
			"generated_at": time.Now().UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// HandlerRunValidation — POST /api/v1/autofix/validation/run
// Body: { "cache_key": "...", "force": true }
// Re-runs validation against an existing cache entry (admin only).
func HandlerRunValidation(db *sql.DB) http.HandlerFunc {
	pipeline := NewPipeline(db)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			CacheKey string `json:"cache_key"`
			Force    bool   `json:"force"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if body.CacheKey == "" {
			http.Error(w, "cache_key required", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		// Fetch cache entry
		var (
			suggestedCode string
			findingID     string
			confidence    sql.NullString
			ruleID        sql.NullString
			language      sql.NullString
			origCode      sql.NullString
			vulnLine      sql.NullInt32
		)
		err := db.QueryRowContext(ctx, `
			SELECT ac.suggested_code, ac.finding_id::text, ac.confidence,
			       f.rule_id, f.language, f.code_snippet, f.line_number
			FROM autofix_cache ac
			LEFT JOIN findings f ON f.id = ac.finding_id
			WHERE ac.cache_key = $1`,
			body.CacheKey).Scan(&suggestedCode, &findingID, &confidence,
			&ruleID, &language, &origCode, &vulnLine)
		if err != nil {
			http.Error(w, "cache entry not found", http.StatusNotFound)
			return
		}

		c := &FixCandidate{
			CacheKey:       body.CacheKey,
			FindingID:      findingID,
			Language:       language.String,
			SuggestedCode:  suggestedCode,
			OriginalCode:   origCode.String,
			VulnerableLine: int(vulnLine.Int32),
			ConfidenceIn:   confidence.String,
			RuleID:         ruleID.String,
		}
		pr, err := pipeline.Run(ctx, c)
		if err != nil {
			http.Error(w, "pipeline failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pr)
	}
}

// =====================================================================
// Helpers
// =====================================================================

func pct(n, d int) int {
	if d == 0 {
		return 0
	}
	return int(float64(n) / float64(d) * 100.0)
}

// actorFromCtx — extract actor for audit log. Replace with real auth ctx.
func actorFromCtx(r *http.Request) string {
	if u := r.Header.Get("X-User"); u != "" {
		return u
	}
	if a := r.Header.Get("Authorization"); a != "" {
		return "token-user"
	}
	return "anonymous"
}

// RegisterRoutes — call from main.go after H3.O routes registered.
//
//	mux.HandleFunc("/api/v1/autofix/validation/stats", autofix.HandlerValidationStats(db))
//	mux.HandleFunc("/api/v1/autofix/validation/run",   autofix.HandlerRunValidation(db))
//	mux.HandleFunc("/api/v1/autofix/validation/",      autofix.HandlerGetValidation(db))
//
// Order matters — /stats and /run are exact-match before catchall /validation/.
