// =====================================================================
// H3.S Auto-PR — SLA Scheduler
// File: internal/autopr/sla_scheduler.go
//
// Periodically scans for cache entries that:
//   - Have validation_status = 'pass' AND validation_score >= sla_min_score
//   - Match severity in repo_config.sla_severity[]
//   - Have NO existing autofix_pr record for the (cache_key, repo_config_id)
//   - Are within sla_max_per_day rate limit
// → Creates PRs automatically
// =====================================================================

package autopr

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"sync"
	"time"
)

// SLAScheduler — autonomous worker
type SLAScheduler struct {
	DB         *sql.DB
	Service    *PRService
	Interval   time.Duration // default 5 minutes
	BatchLimit int            // max PRs per tick (default 5)

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewSLAScheduler — constructor
func NewSLAScheduler(db *sql.DB) *SLAScheduler {
	return &SLAScheduler{
		DB:         db,
		Service:    NewPRService(db),
		Interval:   5 * time.Minute,
		BatchLimit: 5,
		stopCh:     make(chan struct{}),
	}
}

// Start — spawn background goroutine. Idempotent.
func (s *SLAScheduler) Start(ctx context.Context) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Printf("[H3.S] SLA scheduler started interval=%s batch=%d",
			s.Interval, s.BatchLimit)

		// First tick immediate (after 30s grace)
		select {
		case <-time.After(30 * time.Second):
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		}

		ticker := time.NewTicker(s.Interval)
		defer ticker.Stop()

		s.tick(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.tick(ctx)
			}
		}
	}()
}

// Stop — clean shutdown
func (s *SLAScheduler) Stop() {
	select {
	case <-s.stopCh: // already closed
	default:
		close(s.stopCh)
	}
	s.wg.Wait()
}

// tick — one iteration: find candidates, create PRs
func (s *SLAScheduler) tick(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// Load enabled repos with auto_pr_enabled=true
	repos, err := s.loadActiveRepos(tickCtx)
	if err != nil {
		log.Printf("[H3.S] tick: load repos failed: %v", err)
		return
	}
	if len(repos) == 0 {
		return // nothing to do
	}

	for _, repo := range repos {
		select {
		case <-tickCtx.Done():
			return
		default:
		}
		s.processRepo(tickCtx, repo)
	}
}

type slaRepo struct {
	ID           string
	TenantID     sql.NullString
	Severities   []string
	MinScore     int
	MaxPerDay    int
	CountedToday int
}

func (s *SLAScheduler) loadActiveRepos(ctx context.Context) ([]slaRepo, error) {
	q := `SELECT
			id::text,
			tenant_id::text,
			COALESCE(sla_severity, ARRAY['critical','high']),
			COALESCE(sla_min_score, 80),
			COALESCE(sla_max_per_day, 10)
		FROM repo_config
		WHERE enabled = true AND auto_pr_enabled = true`
	rows, err := s.DB.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []slaRepo{}
	for rows.Next() {
		var r slaRepo
		var sevs string // pq array as string
		if err := rows.Scan(&r.ID, &r.TenantID, &sevs, &r.MinScore, &r.MaxPerDay); err != nil {
			continue
		}
		r.Severities = parsePgArray(sevs)
		out = append(out, r)
	}
	return out, nil
}

// parsePgArray — convert "{critical,high}" → []string
func parsePgArray(s string) []string {
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// processRepo — pick eligible cache rows for this repo, create PRs
func (s *SLAScheduler) processRepo(ctx context.Context, repo slaRepo) {
	// Check rate limit first
	var todayCount int
	_ = s.DB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM autofix_pr
		WHERE repo_config_id = $1::uuid AND trigger_type = 'sla'
		AND created_at > NOW() - INTERVAL '24 hours'`,
		repo.ID).Scan(&todayCount)

	available := repo.MaxPerDay - todayCount
	if available <= 0 {
		log.Printf("[H3.S] repo=%s rate limit reached today=%d max=%d",
			repo.ID[:8], todayCount, repo.MaxPerDay)
		return
	}
	if available > s.BatchLimit {
		available = s.BatchLimit
	}

	// Find eligible cache entries:
	// - validation passed with score >= min
	// - severity in allowed list
	// - no existing PR for this (cache_key, repo)
	// - cache entry not expired
	candidates, err := s.loadCandidates(ctx, repo, available)
	if err != nil {
		log.Printf("[H3.S] repo=%s load candidates: %v", repo.ID[:8], err)
		return
	}
	if len(candidates) == 0 {
		return
	}

	log.Printf("[H3.S] repo=%s processing %d candidates (available=%d)",
		repo.ID[:8], len(candidates), available)

	for _, c := range candidates {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, err := s.Service.Create(ctx, &CreatePRInput{
			CacheKey:     c.CacheKey,
			FindingID:    c.FindingID,
			RepoConfigID: repo.ID,
			TriggerType:  "sla",
			CreatedBy:    "sla_scheduler",
		})
		if err != nil {
			log.Printf("[H3.S] sla create failed cache=%s err=%v",
				c.CacheKey[:16], err)
			continue
		}
		log.Printf("[H3.S] sla PR created cache=%s rule=%s score=%d",
			c.CacheKey[:16], c.RuleID, c.Score)
	}
}

type candidate struct {
	CacheKey  string
	FindingID string
	RuleID    string
	Score     int
}

func (s *SLAScheduler) loadCandidates(ctx context.Context, repo slaRepo, limit int) ([]candidate, error) {
	// Build severity list as SQL array param
	sevs := repo.Severities
	if len(sevs) == 0 {
		sevs = []string{"critical", "high"}
	}
	sevArr := "{" + strings.Join(sevs, ",") + "}"

	q := `SELECT
			ac.cache_key,
			ac.finding_id::text,
			COALESCE(f.rule_id, ''),
			COALESCE(ac.validation_score, 0)
		FROM autofix_cache ac
		LEFT JOIN findings f ON f.id::text = ac.finding_id::text
		LEFT JOIN autofix_pr p ON p.cache_key = ac.cache_key
		    AND p.repo_config_id = $1::uuid
		    AND p.pr_status NOT IN ('failed','closed')
		WHERE ac.validation_status = 'pass'
		  AND COALESCE(ac.validation_score, 0) >= $2
		  AND COALESCE(f.severity, 'medium') = ANY($3::text[])
		  AND p.id IS NULL
		  AND ac.expires_at > NOW()
		ORDER BY ac.validation_score DESC, ac.created_at ASC
		LIMIT $4`

	rows, err := s.DB.QueryContext(ctx, q, repo.ID, repo.MinScore, sevArr, limit)
	if err != nil {
		// Fallback: try without findings join (in case schema differs)
		q2 := `SELECT ac.cache_key, ac.finding_id::text, '', COALESCE(ac.validation_score,0)
			FROM autofix_cache ac
			LEFT JOIN autofix_pr p ON p.cache_key = ac.cache_key
			    AND p.repo_config_id = $1::uuid
			    AND p.pr_status NOT IN ('failed','closed')
			WHERE ac.validation_status = 'pass'
			  AND COALESCE(ac.validation_score, 0) >= $2
			  AND p.id IS NULL
			  AND ac.expires_at > NOW()
			ORDER BY ac.validation_score DESC LIMIT $3`
		rows, err = s.DB.QueryContext(ctx, q2, repo.ID, repo.MinScore, limit)
		if err != nil {
			return nil, err
		}
	}
	defer rows.Close()

	out := []candidate{}
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.CacheKey, &c.FindingID, &c.RuleID, &c.Score); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}
