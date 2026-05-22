package poam

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// Worker auto-syncs findings into POAM items in the background.
// Logic copied from /api/v1/poam/sync handler with additions:
//   - CWE → 800-53 mapping (richer than tool-only)
//   - Auto-close POAMs when findings resolve
//   - Idempotent (uses ON CONFLICT DO NOTHING)
type Worker struct {
	db       *sql.DB
	interval time.Duration
}

// New creates a new POAM auto-gen worker.
// db: shared p4DB instance (sql.DB from cmd/gateway/main.go).
// interval: how often to scan for new findings (default: 5 min).
func New(db *sql.DB, interval time.Duration) *Worker {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &Worker{db: db, interval: interval}
}

// Start runs the worker in the current goroutine.
// Blocks until ctx is cancelled. Caller should run in a goroutine.
func (w *Worker) Start(ctx context.Context) {
	log.Info().
		Dur("interval", w.interval).
		Int("cwe_mappings", MappingCount()).
		Msg("poam: auto-gen worker started")

	// Run once on startup (skip 5min wait)
	w.runCycle(ctx)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("poam: worker stopped")
			return
		case <-ticker.C:
			w.runCycle(ctx)
		}
	}
}

// runCycle is one tick of the worker: create new POAMs + close resolved ones.
func (w *Worker) runCycle(ctx context.Context) {
	if w.db == nil {
		return
	}
	created := w.createPOAMsForNewFindings(ctx)
	closed := w.closePOAMsForResolvedFindings(ctx)
	if created+closed > 0 {
		log.Info().Int("created", created).Int("closed", closed).Msg("poam: cycle complete")
	}
}

// createPOAMsForNewFindings is the core logic — copied + enhanced from
// the existing /api/v1/poam/sync handler in main.go:1700-1750.
func (w *Worker) createPOAMsForNewFindings(ctx context.Context) int {
	// Iterate per tenant — required by tenant_id FK
	tenantRows, err := w.db.QueryContext(ctx, `SELECT DISTINCT id FROM tenants`)
	if err != nil {
		log.Warn().Err(err).Msg("poam: tenant query failed")
		return 0
	}
	defer tenantRows.Close()

	var tenantIDs []string
	for tenantRows.Next() {
		var tid string
		if scanErr := tenantRows.Scan(&tid); scanErr == nil {
			tenantIDs = append(tenantIDs, tid)
		}
	}

	totalCreated := 0
	for _, tenantID := range tenantIDs {
		totalCreated += w.syncTenant(ctx, tenantID)
	}
	return totalCreated
}

// syncTenant processes findings for one tenant.
func (w *Worker) syncTenant(ctx context.Context, tenantID string) int {
	rows, err := w.db.QueryContext(ctx, `
		SELECT f.id::text, f.severity, f.tool, COALESCE(f.rule_id,''),
		       COALESCE(f.message,''), COALESCE(f.path,''), COALESCE(f.cwe,'')
		FROM findings f
		WHERE f.tenant_id = $1
		  AND f.severity IN ('CRITICAL','HIGH')
		  AND NOT EXISTS (
		    SELECT 1 FROM p4_poam_items p WHERE p.finding_id = f.id::text
		  )
		ORDER BY
		  CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 END,
		  f.created_at DESC
		LIMIT 100`, tenantID)
	if err != nil {
		log.Warn().Err(err).Str("tenant", tenantID).Msg("poam: findings query failed")
		return 0
	}
	defer rows.Close()

	type fRow struct{ id, sev, tool, rule, msg, path, cwe string }
	var findings []fRow
	for rows.Next() {
		var f fRow
		if scanErr := rows.Scan(&f.id, &f.sev, &f.tool, &f.rule, &f.msg, &f.path, &f.cwe); scanErr == nil {
			findings = append(findings, f)
		}
	}
	if len(findings) == 0 {
		return 0
	}

	// Get next POAM ID
	var maxNum int
	_ = w.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(CAST(SUBSTRING(id FROM 10) AS INTEGER)),0)
		 FROM p4_poam_items WHERE id LIKE 'POAM-VSP-%'`).Scan(&maxNum)

	// Tool-based control mapping (from existing handler) — fallback if no CWE
	toolToControl := map[string]string{
		"semgrep":  "SA-11",
		"bandit":   "SA-11",
		"trivy":    "RA-5",
		"grype":    "RA-5",
		"gitleaks": "IA-5",
		"kics":     "CM-6",
		"checkov":  "CM-6",
		"nuclei":   "CA-2",
		"nikto":    "CA-2",
		"nmap":     "SC-7",
	}

	created := 0
	for i, f := range findings {
		poamID := fmt.Sprintf("POAM-VSP-%03d", maxNum+i+1)

		// Due date by severity (from existing handler)
		due := time.Now().Add(7 * 24 * time.Hour)
		if f.sev == "CRITICAL" {
			due = time.Now().Add(24 * time.Hour)
		}

		// Control mapping: CWE first (more specific), tool fallback, then SI-2
		ctrl := MapCWEToControl(f.cwe) // "SI-2" if unmapped
		if f.cwe == "" || ctrl == "SI-2" {
			if c, ok := toolToControl[f.tool]; ok {
				ctrl = c
			}
		}

		title := f.msg
		if len(title) > 100 {
			title = title[:97] + "..."
		}
		if title == "" {
			title = fmt.Sprintf("[%s] %s finding", f.tool, f.sev)
		}

		mit := fmt.Sprintf("VSP auto-gen. Tool:%s Rule:%s CWE:%s Path:%s",
			f.tool, f.rule, f.cwe, f.path)

		_, insErr := w.db.ExecContext(ctx,
			`INSERT INTO p4_poam_items
			 (id, system_id, weakness_name, control_id, severity, status,
			  mitigation_plan, finding_id, scheduled_completion, tenant_id,
			  created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,'open',$6,$7,$8,$9,NOW(),NOW())
			 ON CONFLICT (id) DO NOTHING`,
			poamID, "VSP-AUTO-GEN", title, ctrl, f.sev, mit, f.id, due, tenantID)

		if insErr == nil {
			created++
		} else {
			log.Warn().Err(insErr).Str("poam_id", poamID).Msg("poam: insert failed")
		}
	}
	return created
}

// closePOAMsForResolvedFindings auto-closes POAMs when their finding is gone.
// "Resolved" here means: finding deleted OR run marked CLOSED.
func (w *Worker) closePOAMsForResolvedFindings(ctx context.Context) int {
	res, err := w.db.ExecContext(ctx, `
		UPDATE p4_poam_items
		SET status = 'closed', updated_at = NOW()
		WHERE status = 'open'
		  AND finding_id IS NOT NULL
		  AND NOT EXISTS (
		    SELECT 1 FROM findings f WHERE f.id::text = p4_poam_items.finding_id
		  )
	`)
	if err != nil {
		log.Warn().Err(err).Msg("poam: close-resolved query failed")
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}
