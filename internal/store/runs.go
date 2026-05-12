package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type Run struct {
	ID            string          `json:"id"`
	RID           string          `json:"rid"`
	TenantID      string          `json:"tenant_id"`
	Mode          string          `json:"mode"`
	Profile       string          `json:"profile"`
	Src           string          `json:"src"`
	TargetURL     string          `json:"target_url"`
	Status        string          `json:"status"`
	Gate          string          `json:"gate"`
	Posture       string          `json:"posture"`
	ToolsDone     int             `json:"tools_done"`
	ToolsTotal    int             `json:"tools_total"`
	TotalFindings int             `json:"total_findings"`
	Summary       json.RawMessage `json:"summary"`
	StartedAt     *time.Time      `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at"`
	CreatedAt     time.Time       `json:"created_at"`
}

const runCols = `id, rid, tenant_id, mode, profile, src, target_url, status,
	gate, posture, tools_done, tools_total, total_findings,
	summary, started_at, finished_at, created_at`

func (db *DB) CreateRun(ctx context.Context, rid, tenantID, mode, profile, src, targetURL string, toolsTotal int) (*Run, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO runs (rid, tenant_id, mode, profile, src, target_url, tools_total)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING `+runCols,
		rid, tenantID, mode, profile, src, targetURL, toolsTotal)
	return scanRun(row)
}

func (db *DB) GetRunByRID(ctx context.Context, tenantID, rid string) (*Run, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT `+runCols+` FROM runs WHERE rid=$1 AND tenant_id=$2 LIMIT 1`,
		rid, tenantID)
	return scanRun(row)
}

// GetRunByID — same as GetRunByRID but matches the UUID primary key.
// Used when UI dropdowns expose run.id (UUID) instead of run.rid (string).
func (db *DB) GetRunByID(ctx context.Context, tenantID, id string) (*Run, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT `+runCols+` FROM runs WHERE id=$1 AND tenant_id=$2 LIMIT 1`,
		id, tenantID)
	return scanRun(row)
}

func (db *DB) GetLatestRun(ctx context.Context, tenantID string) (*Run, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT `+runCols+` FROM runs WHERE tenant_id=$1 AND status='DONE' ORDER BY created_at DESC LIMIT 1`,
		tenantID)
	return scanRun(row)
}

func (db *DB) ListRuns(ctx context.Context, tenantID string, limit, offset int) ([]Run, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 500 {
		limit = 500
	} // hard cap
	rows, err := db.pool.Query(ctx,
		`SELECT `+runCols+` FROM runs WHERE tenant_id=$1
		 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()
	var runs []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		if r == nil {
			continue
		}
		runs = append(runs, *r)
	}
	return runs, nil
}

// CountRuns returns the true row count for the tenant — used by the
// /vsp/runs/index handler so the FE "Total Runs" KPI shows the real
// number instead of `len(page)` which jumped between 50/200 depending
// on which fetch site asked. Cheap: backed by idx_runs_tenant.
func (db *DB) CountRuns(ctx context.Context, tenantID string) (int, error) {
	var n int
	err := db.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM runs WHERE tenant_id = $1`, tenantID).Scan(&n)
	return n, err
}

func (db *DB) UpdateRunStatus(ctx context.Context, tenantID, rid, status string, toolsDone int) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE runs SET status=$3, tools_done=$4,
		  started_at  = CASE WHEN $3='RUNNING' AND started_at IS NULL THEN NOW() ELSE started_at END,
		  finished_at = CASE WHEN $3 IN ('DONE','FAILED','CANCELLED') THEN NOW() ELSE finished_at END
		 WHERE rid=$1 AND tenant_id=$2`,
		rid, tenantID, status, toolsDone)
	return err
}

// UpdateRunResult finalises a run row. toolsDone is the actual number
// of tool runners the worker dispatched (success + fail combined) —
// it must NOT be clamped to tools_total. Pre-2026-05-11 this query
// did `tools_done = tools_total`, which papered over the FULL_SOC
// drift bug: stale tools_total=18 caused the UI to show "18/18"
// regardless of how many tools actually ran. Pass the real count
// from the worker so the operator sees ground truth.
func (db *DB) UpdateRunResult(ctx context.Context, tenantID, rid, gate, posture string, total, toolsDone int, summary json.RawMessage) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE runs
		 SET status='DONE', gate=$3, posture=$4, total_findings=$5,
		     summary=$6, tools_done=$7, finished_at=NOW()
		 WHERE rid=$1 AND tenant_id=$2`,
		rid, tenantID, gate, posture, total, summary, toolsDone)
	return err
}

func scanRun(row scanner) (*Run, error) {
	var r Run
	// NULL-safe scanning for optional fields
	var gate, posture, src, targetURL *string
	err := row.Scan(
		&r.ID, &r.RID, &r.TenantID, &r.Mode, &r.Profile,
		&src, &targetURL, &r.Status, &gate, &posture,
		&r.ToolsDone, &r.ToolsTotal, &r.TotalFindings,
		&r.Summary, &r.StartedAt, &r.FinishedAt, &r.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan run: %w", err)
	}
	if gate != nil {
		r.Gate = *gate
	}
	if posture != nil {
		r.Posture = *posture
	}
	if src != nil {
		r.Src = *src
	}
	if targetURL != nil {
		r.TargetURL = *targetURL
	}
	if r.Summary == nil {
		r.Summary = json.RawMessage("{}")
	}
	return &r, nil
}

// UpdateRunGateReason stores the gate decision reason for audit trail.
func (db *DB) UpdateRunGateReason(ctx context.Context, tenantID, rid, reason string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE runs SET gate_reason=$1 WHERE tenant_id=$2 AND rid=$3`,
		reason, tenantID, rid)
	return err
}
