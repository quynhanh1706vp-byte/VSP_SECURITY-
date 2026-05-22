package autofix

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vsp/platform/internal/llm"
)

// PrecomputeWorker pre-computes AI fixes for CRITICAL/HIGH code findings
// in the background, eliminating 25-40s "Loading diff..." UX latency.
//
// Uses *sql.DB to match H3.N handler pattern (FindingDiffHandler, etc.).
type PrecomputeWorker struct {
	db           *sql.DB
	provider     llm.Provider
	policy       *llm.Policy
	repoRoot     string
	concurrency  int
	batchLimit   int
	pollInterval time.Duration
	runBudget    time.Duration
	severities   []string
	mu           sync.Mutex
	currentJob   *PrecomputeJob
	stopCh       chan struct{}
	health       HealthTicker
}

// NewPrecomputeWorker constructs a worker. Returns nil if dependencies missing.
func NewPrecomputeWorker(
	db *sql.DB,
	provider llm.Provider,
	policy *llm.Policy,
) *PrecomputeWorker {
	if db == nil || provider == nil || policy == nil {
		return nil
	}

	w := &PrecomputeWorker{
		db:           db,
		provider:     provider,
		policy:       policy,
		repoRoot:     getEnvStrAutofix("VSP_REPO_ROOT", "."),
		concurrency:  getEnvIntAutofix("LLM_PRECOMPUTE_CONCURRENCY", 2),
		batchLimit:   getEnvIntAutofix("LLM_PRECOMPUTE_BATCH_LIMIT", 100),
		pollInterval: time.Duration(getEnvIntAutofix("LLM_PRECOMPUTE_POLL_SECONDS", 30)) * time.Second,
		runBudget:    time.Duration(getEnvIntAutofix("LLM_PRECOMPUTE_RUN_BUDGET_SECONDS", 600)) * time.Second,
		severities:   parseSeveritiesAutofix(os.Getenv("LLM_PRECOMPUTE_SEVERITIES")),
		stopCh:       make(chan struct{}),
	}

	if w.concurrency < 1 || w.concurrency > 8 {
		w.concurrency = 2
	}
	if w.batchLimit < 1 || w.batchLimit > 1000 {
		w.batchLimit = 100
	}

	return w
}

// Run is the main loop — call as `go worker.Run(ctx)`.
func (w *PrecomputeWorker) Run(ctx context.Context) {
	log.Info().
		Int("concurrency", w.concurrency).
		Int("batch_limit", w.batchLimit).
		Dur("poll_interval", w.pollInterval).
		Strs("severities", w.severities).
		Msg("[H3.O] Precompute worker started")

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("[H3.O] Precompute worker stopping")
			return
		case <-w.stopCh:
			log.Info().Msg("[H3.O] Precompute worker stopped")
			return
		case <-timer.C:
			w.tick(ctx)
			if w.health != nil {
				w.health.Tick(0, 0)
			}
			timer.Reset(w.pollInterval)
		}
	}
}

func (w *PrecomputeWorker) Stop() {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
}

// SetHealth wires a HealthTicker for liveness reporting via /health/agentic.
func (w *PrecomputeWorker) SetHealth(h HealthTicker) {
	w.health = h
}

func (w *PrecomputeWorker) CurrentJob() *PrecomputeJob {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.currentJob == nil {
		return nil
	}
	jobCopy := *w.currentJob
	return &jobCopy
}

func (w *PrecomputeWorker) setCurrentJob(j *PrecomputeJob) {
	w.mu.Lock()
	w.currentJob = j
	w.mu.Unlock()
}

func (w *PrecomputeWorker) tick(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("[H3.O] Worker tick panic recovered")
		}
	}()

	rows, err := w.db.QueryContext(ctx, `
		SELECT r.id::text, r.tenant_id::text
		FROM runs r
		LEFT JOIN autofix_precompute_jobs j ON j.run_id = r.id
		WHERE LOWER(r.status) IN ('done', 'completed', 'success')
		  AND r.finished_at IS NOT NULL
		  AND r.finished_at > NOW() - INTERVAL '7 days'
		  AND j.id IS NULL
		ORDER BY r.finished_at DESC
		LIMIT 1
	`)
	if err != nil {
		log.Warn().Err(err).Msg("[H3.O] Failed to query pending runs")
		return
	}
	defer rows.Close()

	var runID, tenantID string
	if !rows.Next() {
		return
	}
	if err := rows.Scan(&runID, &tenantID); err != nil {
		log.Warn().Err(err).Msg("[H3.O] Failed to scan run row")
		return
	}
	rows.Close()

	w.processRun(ctx, runID, tenantID)
}

func (w *PrecomputeWorker) processRun(parentCtx context.Context, runID, tenantID string) {
	ctx, cancel := context.WithTimeout(parentCtx, w.runBudget)
	defer cancel()

	findings, err := w.loadEligibleFindings(ctx, runID)
	if err != nil {
		log.Warn().Err(err).Str("run_id", runID).Msg("[H3.O] Failed to load findings")
		return
	}

	if len(findings) == 0 {
		w.insertEmptyJob(ctx, runID, tenantID)
		return
	}

	log.Info().
		Str("run_id", runID).
		Int("eligible", len(findings)).
		Msg("[H3.O] Starting pre-compute job")

	jobID, err := w.createJob(ctx, runID, tenantID, len(findings))
	if err != nil {
		log.Warn().Err(err).Msg("[H3.O] Failed to create job row")
		return
	}

	job := &PrecomputeJob{
		ID:       jobID,
		RunID:    runID,
		TenantID: tenantID,
		Status:   "running",
		Total:    len(findings),
	}
	w.setCurrentJob(job)
	defer w.setCurrentJob(nil)

	sem := make(chan struct{}, w.concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var totalLatencyMs int64
	successCount := 0

	for _, f := range findings {
		// SA4011 fix: bare `break` inside select only breaks the
		// select, not the outer for. Check ctx directly so a cancel
		// actually stops scheduling new goroutines.
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(finding PrecomputeFinding) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Interface("panic", r).
						Str("finding", finding.ID).
						Msg("[H3.O] Per-finding panic recovered")
				}
			}()

			outcome, latency := w.processFinding(ctx, finding)

			mu.Lock()
			defer mu.Unlock()
			switch outcome {
			case "completed":
				job.Completed++
				totalLatencyMs += int64(latency)
				successCount++
			case "skipped":
				job.Skipped++
			case "failed":
				job.Failed++
			}

			if (job.Completed+job.Failed+job.Skipped)%5 == 0 {
				avg := 0
				if successCount > 0 {
					avg = int(totalLatencyMs / int64(successCount))
				}
				w.updateJobProgress(ctx, jobID, job.Completed, job.Failed, job.Skipped, avg)
			}
		}(f)
	}
	wg.Wait()

	avg := 0
	if successCount > 0 {
		avg = int(totalLatencyMs / int64(successCount))
	}
	w.finalizeJob(parentCtx, jobID, job.Completed, job.Failed, job.Skipped, avg)

	log.Info().
		Str("run_id", runID).
		Int("completed", job.Completed).
		Int("failed", job.Failed).
		Int("skipped", job.Skipped).
		Int("avg_latency_ms", avg).
		Msg("[H3.O] Pre-compute job finished")
}

func (w *PrecomputeWorker) processFinding(ctx context.Context, f PrecomputeFinding) (string, int) {
	if !w.policy.AllowLLM(f.RuleID) {
		log.Debug().Str("finding", f.ID).Str("rule", f.RuleID).Msg("[H3.O] skipped: policy block")
		return "skipped", 0
	}

	currLines, beforeLines, afterLines, err := w.readContext(f.Path, f.LineNum)
	if err != nil || len(currLines) == 0 {
		log.Debug().Err(err).Str("finding", f.ID).Str("path", f.Path).Int("line", f.LineNum).Msg("[H3.O] skipped: readContext failed")
		return "skipped", 0
	}

	req := llm.FixRequest{
		RuleID:          f.RuleID,
		RuleDescription: f.Message,
		FilePath:        f.Path,
		Language:        llm.LanguageFromPath(f.Path),
		CodeBefore:      strings.Join(beforeLines, "\n"),
		VulnerableCode:  strings.Join(currLines, "\n"),
		CodeAfter:       strings.Join(afterLines, "\n"),
		Severity:        strings.ToLower(f.Severity),
	}

	cacheKey := llm.CacheKey(req)
	if w.isCached(ctx, cacheKey) {
		log.Debug().Str("finding", f.ID).Msg("[H3.O] skipped: already cached")
		return "skipped", 0
	}

	llmCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	start := time.Now()
	resp, err := w.provider.GenerateFix(llmCtx, req)
	latency := int(time.Since(start) / time.Millisecond)

	if err != nil {
		log.Debug().Err(err).Str("finding", f.ID).Str("rule", f.RuleID).
			Msg("[H3.O] LLM call failed")
		return "failed", latency
	}

	conf := strings.ToLower(strings.TrimSpace(resp.Confidence))
	if conf != "high" && conf != "medium" && conf != "low" {
		conf = "low"
	}
	resp.Confidence = conf

	if resp.Provider == "" {
		resp.Provider = w.provider.Name()
	}
	if resp.Model == "" {
		resp.Model = os.Getenv("LLM_MODEL")
		if resp.Model == "" {
			resp.Model = "unknown"
		}
	}
	if resp.LatencyMs == 0 {
		resp.LatencyMs = int64(latency)
	}

	// ── H3.Q validation gate ──────────────────────────────────────
	// Validate the LLM-produced fix BEFORE persisting to autofix_cache.
	// If the gate rejects, we skip CacheSet entirely so users never see
	// a broken/regressed fix. Validation results are persisted regardless
	// (telemetry on rejected fixes is also valuable).
	candidate := &FixCandidate{
		CacheKey:       cacheKey,
		FindingID:      f.ID,
		Language:       req.Language,
		OriginalCode:   req.VulnerableCode,
		SuggestedCode:  resp.SuggestedCode,
		VulnerableLine: f.LineNum,
		ConfidenceIn:   resp.Confidence,
		RuleID:         f.RuleID,
	}
	valCtx, valCancel := context.WithTimeout(ctx, 60*time.Second)
	pipeline := NewPipeline(w.db)
	pr, valErr := pipeline.Run(valCtx, candidate)
	valCancel()
	if valErr != nil {
		log.Debug().Err(valErr).Str("finding", f.ID).
			Msg("[H3.Q] pipeline error — proceeding without gate")
	} else {
		gate := DefaultGate()
		if ok, reason := gate.ShouldCache(pr); !ok {
			log.Info().
				Str("finding", f.ID).
				Str("rule", f.RuleID).
				Int("score", pr.Score).
				Str("status", pr.OverallStatus).
				Str("reason", reason).
				Msg("[H3.Q] fix rejected — not cached")
			return "rejected", latency
		}
		// Downgrade confidence if validation reduced it
		if pr.ConfidenceFinal != "" && pr.ConfidenceFinal != resp.Confidence {
			log.Info().
				Str("finding", f.ID).
				Str("conf_in", resp.Confidence).
				Str("conf_out", pr.ConfidenceFinal).
				Int("score", pr.Score).
				Msg("[H3.Q] confidence downgraded by validation")
			resp.Confidence = pr.ConfidenceFinal
		}
	}
	// ── end H3.Q gate ─────────────────────────────────────────────

	// Reuse llm.CacheSet via sql.DB → PgxQuerier adapter
	adapter := newSQLAdapter(w.db)
	if err := llm.CacheSet(ctx, adapter, cacheKey, f.ID, resp, 30*24*time.Hour); err != nil {
		log.Debug().Err(err).Msg("[H3.O] Cache set failed")
		return "failed", latency
	}

	w.auditLog(ctx, f, latency, conf)
	return "completed", latency
}

func (w *PrecomputeWorker) readContext(path string, lineNum int) ([]string, []string, []string, error) {
	if path == "" || lineNum <= 0 {
		return nil, nil, nil, fmt.Errorf("invalid path/line")
	}

	var absFile string
	var err error
	if filepath.IsAbs(path) {
		absFile, err = filepath.Abs(path)
	} else {
		absRepo, _ := filepath.Abs(w.repoRoot)
		absFile, err = filepath.Abs(filepath.Join(absRepo, path))
	}
	if err != nil {
		return nil, nil, nil, err
	}

	absRepo, _ := filepath.Abs(w.repoRoot)
	if !strings.HasPrefix(absFile, absRepo) && !strings.HasPrefix(absFile, "/tmp/") {
		return nil, nil, nil, fmt.Errorf("path outside allowed roots")
	}

	data, err := os.ReadFile(absFile)
	if err != nil {
		return nil, nil, nil, err
	}

	lines := strings.Split(string(data), "\n")
	if lineNum > len(lines) {
		return nil, nil, nil, fmt.Errorf("line %d out of range", lineNum)
	}

	idx := lineNum - 1
	beforeStart := idx - 5
	if beforeStart < 0 {
		beforeStart = 0
	}
	afterEnd := idx + 6
	if afterEnd > len(lines) {
		afterEnd = len(lines)
	}

	return lines[idx : idx+1], lines[beforeStart:idx], lines[idx+1 : afterEnd], nil
}

func (w *PrecomputeWorker) loadEligibleFindings(ctx context.Context, runID string) ([]PrecomputeFinding, error) {
	if len(w.severities) == 0 {
		return nil, fmt.Errorf("no severities configured")
	}
	sevPlaceholders := make([]string, len(w.severities))
	args := make([]interface{}, 0, len(w.severities)+2)
	args = append(args, runID, w.batchLimit)
	for i, s := range w.severities {
		sevPlaceholders[i] = fmt.Sprintf("$%d", i+3)
		args = append(args, strings.ToUpper(s))
	}

	// #nosec G201 -- sevPlaceholders is a slice of "$N" placeholders generated
	// in the loop above; user severity values flow through $3..$N parameterized
	// binds, never into the SQL text.
	query := fmt.Sprintf(`
		SELECT f.id::text, COALESCE(f.rule_id,''), f.severity,
		       COALESCE(f.path,''), COALESCE(f.line_num, 0),
		       COALESCE(f.message,''), f.tool
		FROM findings f
		WHERE f.run_id = $1
		  AND UPPER(f.severity) IN (%s)
		  AND COALESCE(f.path,'') != ''
		  AND COALESCE(f.line_num, 0) > 0
		ORDER BY
		  CASE UPPER(f.severity) WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END,
		  f.created_at DESC
		LIMIT $2
	`, strings.Join(sevPlaceholders, ","))

	rows, err := w.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PrecomputeFinding
	for rows.Next() {
		var f PrecomputeFinding
		if err := rows.Scan(&f.ID, &f.RuleID, &f.Severity, &f.Path,
			&f.LineNum, &f.Message, &f.Tool); err != nil {
			continue
		}
		if !IsCodeFile(f.Path) {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func (w *PrecomputeWorker) isCached(ctx context.Context, cacheKey string) bool {
	var exists bool
	err := w.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM autofix_cache 
		              WHERE cache_key = $1 AND expires_at > NOW())
	`, cacheKey).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

func (w *PrecomputeWorker) createJob(ctx context.Context, runID, tenantID string, total int) (string, error) {
	var id string
	err := w.db.QueryRowContext(ctx, `
		INSERT INTO autofix_precompute_jobs
		  (run_id, tenant_id, status, total, started_at)
		VALUES ($1, $2, 'running', $3, NOW())
		ON CONFLICT (run_id) DO UPDATE
		  SET status = 'running', total = EXCLUDED.total, started_at = NOW()
		RETURNING id::text
	`, runID, tenantID, total).Scan(&id)
	return id, err
}

func (w *PrecomputeWorker) insertEmptyJob(ctx context.Context, runID, tenantID string) {
	_, _ = w.db.ExecContext(ctx, `
		INSERT INTO autofix_precompute_jobs
		  (run_id, tenant_id, status, total, started_at, finished_at)
		VALUES ($1, $2, 'done', 0, NOW(), NOW())
		ON CONFLICT (run_id) DO NOTHING
	`, runID, tenantID)
}

func (w *PrecomputeWorker) updateJobProgress(ctx context.Context, jobID string, completed, failed, skipped, avgLatency int) {
	_, _ = w.db.ExecContext(ctx, `
		UPDATE autofix_precompute_jobs
		SET completed=$2, failed=$3, skipped=$4, avg_latency_ms=$5
		WHERE id=$1::uuid
	`, jobID, completed, failed, skipped, avgLatency)

	w.mu.Lock()
	if w.currentJob != nil && w.currentJob.ID == jobID {
		w.currentJob.Completed = completed
		w.currentJob.Failed = failed
		w.currentJob.Skipped = skipped
		w.currentJob.AvgLatency = avgLatency
	}
	w.mu.Unlock()
}

func (w *PrecomputeWorker) finalizeJob(ctx context.Context, jobID string, completed, failed, skipped, avgLatency int) {
	_, _ = w.db.ExecContext(ctx, `
		UPDATE autofix_precompute_jobs
		SET status='done', completed=$2, failed=$3, skipped=$4,
		    avg_latency_ms=$5, finished_at=NOW()
		WHERE id=$1::uuid
	`, jobID, completed, failed, skipped, avgLatency)
}

func (w *PrecomputeWorker) auditLog(ctx context.Context, f PrecomputeFinding, latencyMs int, confidence string) {
	meta, _ := json.Marshal(map[string]interface{}{
		"finding_id": f.ID,
		"rule_id":    f.RuleID,
		"severity":   f.Severity,
		"latency_ms": latencyMs,
		"confidence": confidence,
		"source":     "precompute",
	})
	_, _ = w.db.ExecContext(ctx, `
		INSERT INTO audit_log (action, entity_type, entity_id, meta, created_at)
		VALUES ('llm_precompute_fix', 'finding', $1, $2, NOW())
	`, f.ID, string(meta))
}

// ────────────────────────────────────────────────────────────────────────────
// sql.DB → llm.PgxQuerier adapter (for llm.CacheSet reuse)
// ────────────────────────────────────────────────────────────────────────────

type sqlAdapter struct {
	db *sql.DB
}

func newSQLAdapter(db *sql.DB) *sqlAdapter {
	return &sqlAdapter{db: db}
}

type sqlRowAdapter struct {
	row *sql.Row
}

func (r *sqlRowAdapter) Scan(dest ...interface{}) error {
	return r.row.Scan(dest...)
}

func (a *sqlAdapter) QueryRow(ctx context.Context, query string, args ...interface{}) llm.PgxRow {
	return &sqlRowAdapter{row: a.db.QueryRowContext(ctx, query, args...)}
}

func (a *sqlAdapter) Exec(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	return a.db.ExecContext(ctx, query, args...)
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

func getEnvStrAutofix(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvIntAutofix(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func parseSeveritiesAutofix(s string) []string {
	if s == "" {
		return []string{"CRITICAL", "HIGH"}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToUpper(p))
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"CRITICAL", "HIGH"}
	}
	return out
}
