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

func (db *DB) GetLatestRun(ctx context.Context, tenantID string) (*Run, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT `+runCols+` FROM runs WHERE tenant_id=$1 AND status='DONE' AND total_findings > 0 ORDER BY created_at DESC LIMIT 1`,
		tenantID)
	return scanRun(row)
}

func (db *DB) ListRuns(ctx context.Context, tenantID string, limit, offset int) ([]Run, error) {
	if limit <= 0  { limit = 20   }
	if limit > 500 { limit = 500  } // hard cap
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
		if r == nil { continue }
		runs = append(runs, *r)
	}
	return runs, nil
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

func (db *DB) UpdateRunResult(ctx context.Context, tenantID, rid, gate, posture string, total int, summary json.RawMessage) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE runs
		 SET status='DONE', gate=$3, posture=$4, total_findings=$5,
		     summary=$6, tools_done=tools_total, finished_at=NOW()
		 WHERE rid=$1 AND tenant_id=$2`,
		rid, tenantID, gate, posture, total, summary)
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
	if gate      != nil { r.Gate      = *gate }
	if posture   != nil { r.Posture   = *posture }
	if src       != nil { r.Src       = *src }
	if targetURL != nil { r.TargetURL = *targetURL }
	if r.Summary == nil { r.Summary   = json.RawMessage("{}") }
	return &r, nil
}

// UpdateRunGateReason stores the gate decision reason for audit trail.
func (db *DB) UpdateRunGateReason(ctx context.Context, tenantID, rid, reason string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE runs SET gate_reason=$1 WHERE tenant_id=$2 AND rid=$3`,
		reason, tenantID, rid)
	return err
}

