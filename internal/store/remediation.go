package store

import (
	"context"
	"fmt"
	"time"
)

type RemediationStatus string

const (
	RemOpen       RemediationStatus = "open"
	RemInProgress RemediationStatus = "in_progress"
	RemResolved   RemediationStatus = "resolved"
	RemAccepted   RemediationStatus = "accepted" // risk accepted
	RemFalsePos   RemediationStatus = "false_positive"
	RemSuppressed RemediationStatus = "suppressed"
)

type Remediation struct {
	ID          string            `json:"id"`
	FindingID   string            `json:"finding_id"`
	TenantID    string            `json:"tenant_id"`
	Status      RemediationStatus `json:"status"`
	Assignee    string            `json:"assignee"`
	Priority    string            `json:"priority"` // P1/P2/P3/P4
	DueDate     *time.Time        `json:"due_date,omitempty"`
	Notes       string            `json:"notes"`
	TicketURL   string            `json:"ticket_url"`
	ResolvedAt  *time.Time        `json:"resolved_at,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type RemediationComment struct {
	ID            string    `json:"id"`
	RemediationID string    `json:"remediation_id"`
	Author        string    `json:"author"`
	Body          string    `json:"body"`
	CreatedAt     time.Time `json:"created_at"`
}

func (db *DB) EnsureRemediationTable(ctx context.Context) error {
	_, err := db.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS remediations (
			id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			finding_id  UUID NOT NULL,
			tenant_id   UUID NOT NULL,
			status      TEXT NOT NULL DEFAULT 'open',
			assignee    TEXT NOT NULL DEFAULT '',
			priority    TEXT NOT NULL DEFAULT 'P3',
			due_date    TIMESTAMPTZ,
			notes       TEXT NOT NULL DEFAULT '',
			ticket_url  TEXT NOT NULL DEFAULT '',
			resolved_at TIMESTAMPTZ,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS remediation_comments (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			remediation_id  UUID NOT NULL REFERENCES remediations(id) ON DELETE CASCADE,
			author          TEXT NOT NULL,
			body            TEXT NOT NULL,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_rem_finding ON remediations(finding_id);
		CREATE INDEX IF NOT EXISTS idx_rem_tenant  ON remediations(tenant_id);
	`)
	return err
}

func (db *DB) GetRemediation(ctx context.Context, tenantID, findingID string) (*Remediation, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT id,finding_id,tenant_id,status,assignee,priority,due_date,
		        notes,ticket_url,resolved_at,created_at,updated_at
		 FROM remediations WHERE finding_id=$1 AND tenant_id=$2 LIMIT 1`,
		findingID, tenantID)
	var r Remediation
	err := row.Scan(&r.ID, &r.FindingID, &r.TenantID, &r.Status,
		&r.Assignee, &r.Priority, &r.DueDate, &r.Notes,
		&r.TicketURL, &r.ResolvedAt, &r.CreatedAt, &r.UpdatedAt)
	if err != nil { return nil, err }
	return &r, nil
}

func (db *DB) UpsertRemediation(ctx context.Context, r Remediation) (*Remediation, error) {
	now := time.Now()
	var resolvedAt interface{} = nil
	if r.Status == RemediationStatus(RemResolved) || r.Status == RemediationStatus(RemFalsePos) {
		resolvedAt = now
	}
	row := db.pool.QueryRow(ctx,
		`INSERT INTO remediations (finding_id,tenant_id,status,assignee,priority,due_date,notes,ticket_url,resolved_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (finding_id) DO UPDATE SET
			status=$3, assignee=$4, priority=$5, due_date=$6,
			notes=$7, ticket_url=$8, resolved_at=COALESCE($9,remediations.resolved_at),
			updated_at=NOW()
		 RETURNING id,finding_id,tenant_id,status,assignee,priority,due_date,
		           notes,ticket_url,resolved_at,created_at,updated_at`,
		r.FindingID, r.TenantID, r.Status, r.Assignee, r.Priority,
		r.DueDate, r.Notes, r.TicketURL, resolvedAt)
	var out Remediation
	err := row.Scan(&out.ID, &out.FindingID, &out.TenantID, &out.Status,
		&out.Assignee, &out.Priority, &out.DueDate, &out.Notes,
		&out.TicketURL, &out.ResolvedAt, &out.CreatedAt, &out.UpdatedAt)
	if err != nil { return nil, fmt.Errorf("upsert remediation: %w", err) }
	return &out, nil
}

func (db *DB) ListRemediations(ctx context.Context, tenantID, status string) ([]Remediation, error) {
	where := "tenant_id=$1"
	args := []any{tenantID}
	if status != "" {
		where += " AND status=$2"
		args = append(args, status)
	}
	rows, err := db.pool.Query(ctx,
		`SELECT id,finding_id,tenant_id,status,assignee,priority,due_date,
		        notes,ticket_url,resolved_at,created_at,updated_at
		 FROM remediations WHERE `+where+` ORDER BY updated_at DESC LIMIT 200`,
		args...)
	if err != nil { return nil, err }
	defer rows.Close()
	var list []Remediation
	for rows.Next() {
		var r Remediation
		rows.Scan(&r.ID, &r.FindingID, &r.TenantID, &r.Status,
			&r.Assignee, &r.Priority, &r.DueDate, &r.Notes,
			&r.TicketURL, &r.ResolvedAt, &r.CreatedAt, &r.UpdatedAt) //nolint
		list = append(list, r)
	}
	return list, nil
}

func (db *DB) AddComment(ctx context.Context, remID, author, body string) (*RemediationComment, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO remediation_comments (remediation_id,author,body)
		 VALUES ($1,$2,$3) RETURNING id,remediation_id,author,body,created_at`,
		remID, author, body)
	var c RemediationComment
	err := row.Scan(&c.ID, &c.RemediationID, &c.Author, &c.Body, &c.CreatedAt)
	if err != nil { return nil, err }
	return &c, nil
}

func (db *DB) ListComments(ctx context.Context, remID string) ([]RemediationComment, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id,remediation_id,author,body,created_at
		 FROM remediation_comments WHERE remediation_id=$1 ORDER BY created_at ASC`,
		remID)
	if err != nil { return nil, err }
	defer rows.Close()
	var list []RemediationComment
	for rows.Next() {
		var c RemediationComment
		rows.Scan(&c.ID, &c.RemediationID, &c.Author, &c.Body, &c.CreatedAt) //nolint
		list = append(list, c)
	}
	return list, nil
}

func (db *DB) RemediationStats(ctx context.Context, tenantID string) (map[string]int, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT status, COUNT(*) FROM remediations WHERE tenant_id=$1 GROUP BY status`,
		tenantID)
	if err != nil { return nil, err }
	defer rows.Close()
	stats := map[string]int{"open":0,"in_progress":0,"resolved":0,"accepted":0,"false_positive":0,"suppressed":0}
	for rows.Next() {
		var s string; var n int
		rows.Scan(&s, &n) //nolint
		stats[s] = n
	}
	return stats, nil
}
