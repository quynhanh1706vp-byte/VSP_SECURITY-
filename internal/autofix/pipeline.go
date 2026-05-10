// =====================================================================
// H3.Q Fix Validation Pipeline — Orchestrator
// File: internal/autofix/validation_pipeline.go
// =====================================================================

package autofix

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// PipelineResult — aggregate output of running all validators on a fix.
type PipelineResult struct {
	CacheKey        string             `json:"cache_key"`
	FindingID       string             `json:"finding_id"`
	OverallStatus   string             `json:"overall_status"` // "pass" | "fail" | "partial"
	Score           int                `json:"score"`          // 0-100
	ConfidenceIn    string             `json:"confidence_in"`
	ConfidenceFinal string             `json:"confidence_final"` // possibly downgraded
	Results         []ValidationResult `json:"results"`
	TotalDurationMs int                `json:"total_duration_ms"`
	ValidatedAt     time.Time          `json:"validated_at"`
}

// Pipeline — orchestrates validators and persists results.
type Pipeline struct {
	DB         *sql.DB
	Validators []Validator
	// FailFast — if true, abort remaining validators after first fail (fast-fail mode).
	// Default false (collect all results for richer telemetry).
	FailFast bool
	// Concurrent — run validators in parallel (each with own timeout). Default false (sequential).
	// Set true only if validators are pure-CPU and don't share tmp dirs (current set is safe).
	Concurrent bool
	// Logger
	Log *log.Logger
}

func NewPipeline(db *sql.DB) *Pipeline {
	return &Pipeline{
		DB:         db,
		Validators: DefaultValidators(),
		Concurrent: false,
		Log:        log.Default(),
	}
}

// Run — execute pipeline against a candidate. Persists results + updates autofix_cache.
func (p *Pipeline) Run(ctx context.Context, c *FixCandidate) (*PipelineResult, error) {
	if c == nil || c.CacheKey == "" {
		return nil, fmt.Errorf("invalid candidate")
	}
	start := time.Now()

	results := make([]ValidationResult, 0, len(p.Validators))
	if p.Concurrent {
		results = p.runConcurrent(ctx, c)
	} else {
		results = p.runSequential(ctx, c)
	}

	pr := &PipelineResult{
		CacheKey:        c.CacheKey,
		FindingID:       c.FindingID,
		ConfidenceIn:    c.ConfidenceIn,
		Results:         results,
		ValidatedAt:     time.Now(),
		TotalDurationMs: int(time.Since(start).Milliseconds()),
	}
	pr.OverallStatus, pr.Score = aggregateStatus(results)
	pr.ConfidenceFinal = applyConfidenceGate(c.ConfidenceIn, pr.OverallStatus, pr.Score)

	if err := p.persist(ctx, pr); err != nil {
		// Log but don't fail — cache update is best-effort
		if p.Log != nil {
			p.Log.Printf("[H3.Q] persist failed: %v", err)
		}
	}

	if p.Log != nil {
		p.Log.Printf("[H3.Q] %s finding=%s status=%s score=%d conf=%s→%s dur=%dms",
			c.CacheKey[:12], c.FindingID, pr.OverallStatus, pr.Score,
			pr.ConfidenceIn, pr.ConfidenceFinal, pr.TotalDurationMs)
	}

	return pr, nil
}

func (p *Pipeline) runSequential(ctx context.Context, c *FixCandidate) []ValidationResult {
	out := make([]ValidationResult, 0, len(p.Validators))
	for _, v := range p.Validators {
		if !v.Applies(c) {
			out = append(out, ValidationResult{
				Validator:  v.Name(),
				Status:     StatusSkip,
				Metadata:   map[string]any{"reason": "not applicable"},
				DurationMs: 0,
			})
			continue
		}
		r := safeRun(ctx, v, c)
		out = append(out, r)
		if p.FailFast && r.Status == StatusFail {
			break
		}
	}
	return out
}

func (p *Pipeline) runConcurrent(ctx context.Context, c *FixCandidate) []ValidationResult {
	var wg sync.WaitGroup
	out := make([]ValidationResult, len(p.Validators))
	for i, v := range p.Validators {
		if !v.Applies(c) {
			out[i] = ValidationResult{
				Validator: v.Name(),
				Status:    StatusSkip,
				Metadata:  map[string]any{"reason": "not applicable"},
			}
			continue
		}
		wg.Add(1)
		go func(idx int, val Validator) {
			defer wg.Done()
			out[idx] = safeRun(ctx, val, c)
		}(i, v)
	}
	wg.Wait()
	return out
}

func safeRun(ctx context.Context, v Validator, c *FixCandidate) (r ValidationResult) {
	defer func() {
		if x := recover(); x != nil {
			r = ValidationResult{
				Validator: v.Name(),
				Status:    StatusError,
				ErrorMsg:  fmt.Sprintf("panic: %v", x),
			}
		}
	}()
	return v.Run(ctx, c)
}

// aggregateStatus — overall verdict + 0-100 score.
// Weights: line_scope=15, lint=25, syntax=20, ast_diff=15, idempotent=10, compile=15
func aggregateStatus(results []ValidationResult) (string, int) {
	weights := map[string]int{
		"line_scope": 15,
		"lint":       25,
		"syntax":     20,
		"ast_diff":   15,
		"idempotent": 10,
		"compile":    15,
	}

	totalWeight := 0
	earnedWeight := 0
	failCount := 0
	hasResults := false

	for _, r := range results {
		w, ok := weights[r.Validator]
		if !ok {
			continue
		}
		switch r.Status {
		case StatusPass:
			totalWeight += w
			earnedWeight += w
			hasResults = true
		case StatusFail:
			totalWeight += w
			failCount++
			hasResults = true
		case StatusError:
			totalWeight += w / 2
			failCount++
			hasResults = true
		case StatusSkip:
			// don't count toward total
		}
	}

	if !hasResults || totalWeight == 0 {
		return "partial", 0
	}
	score := int(float64(earnedWeight) / float64(totalWeight) * 100.0)

	switch {
	case failCount == 0 && earnedWeight == totalWeight:
		return "pass", score
	case failCount > 0 && score >= 70:
		return "partial", score
	default:
		return "fail", score
	}
}

// applyConfidenceGate — downgrade LLM-reported confidence based on validation outcome.
// Rules:
//
//	pass + score≥90  → keep
//	pass + score<90  → downgrade by 1 step
//	partial          → downgrade by 1 step (cap at "low")
//	fail             → "low" regardless of input
func applyConfidenceGate(in, status string, score int) string {
	in = strings.ToLower(strings.TrimSpace(in))
	if in == "" {
		in = "medium"
	}
	if status == "fail" {
		return "low"
	}
	if status == "pass" && score >= 90 {
		return in
	}
	switch in {
	case "high":
		return "medium"
	case "medium":
		return "low"
	default:
		return "low"
	}
}

// persist — write to autofix_validation + update autofix_cache summary
func (p *Pipeline) persist(ctx context.Context, pr *PipelineResult) error {
	if p.DB == nil {
		return nil
	}
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	stmt := `INSERT INTO autofix_validation
		(cache_key, finding_id, validator, status, confidence_in, confidence_out,
		 duration_ms, error_msg, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`

	for _, r := range pr.Results {
		md, _ := json.Marshal(r.Metadata)
		if _, err := tx.ExecContext(ctx, stmt,
			pr.CacheKey, pr.FindingID, r.Validator, string(r.Status),
			pr.ConfidenceIn, pr.ConfidenceFinal,
			r.DurationMs, r.ErrorMsg, string(md),
		); err != nil {
			return fmt.Errorf("insert validator=%s: %w", r.Validator, err)
		}
	}

	// Update denorm columns on autofix_cache (no source code stored here — CMMC AU-2)
	upd := `UPDATE autofix_cache
		SET validation_score = $1,
		    validation_status = $2,
		    validation_at = NOW(),
		    confidence_final = $3
		WHERE cache_key = $4`
	if _, err := tx.ExecContext(ctx, upd,
		pr.Score, pr.OverallStatus, pr.ConfidenceFinal, pr.CacheKey); err != nil {
		return fmt.Errorf("update cache: %w", err)
	}

	return tx.Commit()
}

// LookupByCacheKey — fetch latest validation results for a cache_key (UI / API)
func (p *Pipeline) LookupByCacheKey(ctx context.Context, cacheKey string) (*PipelineResult, error) {
	if p.DB == nil {
		return nil, fmt.Errorf("nil db")
	}
	q := `SELECT validator, status, duration_ms, error_msg, metadata,
	             confidence_in, confidence_out, finding_id::text, created_at
	      FROM autofix_validation
	      WHERE cache_key = $1
	      ORDER BY created_at DESC, id DESC
	      LIMIT 20`
	rows, err := p.DB.QueryContext(ctx, q, cacheKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	pr := &PipelineResult{CacheKey: cacheKey, Results: []ValidationResult{}}
	seen := map[string]bool{}
	var (
		findingID   string
		validatedAt time.Time
	)
	for rows.Next() {
		var (
			r       ValidationResult
			status  string
			mdRaw   []byte
			confIn  sql.NullString
			confOut sql.NullString
		)
		if err := rows.Scan(&r.Validator, &status, &r.DurationMs, &r.ErrorMsg,
			&mdRaw, &confIn, &confOut, &findingID, &validatedAt); err != nil {
			return nil, err
		}
		if seen[r.Validator] {
			continue // keep only latest per validator
		}
		seen[r.Validator] = true
		r.Status = ValidationStatus(status)
		_ = json.Unmarshal(mdRaw, &r.Metadata)
		pr.Results = append(pr.Results, r)
		if pr.ConfidenceIn == "" && confIn.Valid {
			pr.ConfidenceIn = confIn.String
		}
		if pr.ConfidenceFinal == "" && confOut.Valid {
			pr.ConfidenceFinal = confOut.String
		}
		if pr.ValidatedAt.IsZero() {
			pr.ValidatedAt = validatedAt
		}
	}
	pr.FindingID = findingID
	pr.OverallStatus, pr.Score = aggregateStatus(pr.Results)
	return pr, nil
}
