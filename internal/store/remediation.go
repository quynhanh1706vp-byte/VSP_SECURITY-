package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
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
	ID         string            `json:"id"`
	FindingID  string            `json:"finding_id"`
	TenantID   string            `json:"tenant_id"`
	Status     RemediationStatus `json:"status"`
	Assignee   string            `json:"assignee"`
	Priority   string            `json:"priority"` // P1/P2/P3/P4
	DueDate    *time.Time        `json:"due_date,omitempty"`
	Notes      string            `json:"notes"`
	TicketURL  string            `json:"ticket_url"`
	ResolvedAt *time.Time        `json:"resolved_at,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	// Joined from findings
	Title    string `json:"title,omitempty"`
	Severity string `json:"severity,omitempty"`
	Tool     string `json:"tool,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
}

type RemediationComment struct {
	ID            string    `json:"id"`
	RemediationID string    `json:"remediation_id"`
	Author        string    `json:"author"`
	Body          string    `json:"body"`
	CreatedAt     time.Time `json:"created_at"`
}

func (db *DB) GetRemediation(ctx context.Context, tenantID, findingID string) (*Remediation, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT r.id,r.finding_id,r.tenant_id,r.status,r.assignee,r.priority,r.due_date,
		        r.notes,r.ticket_url,r.resolved_at,r.created_at,r.updated_at,
		        COALESCE(f.message,'') as title, COALESCE(f.severity,'') as severity,
		        COALESCE(f.tool,'') as tool, COALESCE(f.rule_id,'') as rule_id
		 FROM remediations r
		 LEFT JOIN findings f ON f.id=r.finding_id
		 WHERE r.finding_id=$1 AND r.tenant_id=$2 LIMIT 1`,
		findingID, tenantID)
	var r Remediation
	err := row.Scan(&r.ID, &r.FindingID, &r.TenantID, &r.Status,
		&r.Assignee, &r.Priority, &r.DueDate, &r.Notes,
		&r.TicketURL, &r.ResolvedAt, &r.CreatedAt, &r.UpdatedAt,
		&r.Title, &r.Severity, &r.Tool, &r.RuleID)
	if err != nil {
		return nil, err
	}
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
	if err != nil {
		return nil, fmt.Errorf("upsert remediation: %w", err)
	}
	return &out, nil
}

// CountRemediations — true row count for the tenant, optionally filtered
// by status (mirrors ListRemediations filter semantics). The list query
// caps at LIMIT 200; without this helper the handler reports
// "total: len(list)" which jams at 200 even when the tenant has the
// 55,712 remediations we actually see on the dashboard.
func (db *DB) CountRemediations(ctx context.Context, tenantID, status string) (int, error) {
	var statusFilter any
	if status != "" {
		statusFilter = status
	}
	var n int
	err := db.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM remediations
		WHERE tenant_id = $1
		  AND ($2::text IS NULL OR status = $2)
	`, tenantID, statusFilter).Scan(&n)
	return n, err
}

func (db *DB) ListRemediations(ctx context.Context, tenantID, status string) ([]Remediation, error) {
	where := "r.tenant_id=$1"
	args := []any{tenantID}
	if status != "" {
		where += " AND r.status=$2"
		args = append(args, status)
	}
	rows, err := db.pool.Query(ctx,
		`SELECT r.id,r.finding_id,r.tenant_id,r.status,r.assignee,r.priority,r.due_date,
		        r.notes,r.ticket_url,r.resolved_at,r.created_at,r.updated_at,
		        COALESCE(f.message,'') as title, COALESCE(f.severity,'') as severity,
		        COALESCE(f.tool,'') as tool, COALESCE(f.rule_id,'') as rule_id
		 FROM remediations r
		 LEFT JOIN findings f ON f.id=r.finding_id AND f.tenant_id=r.tenant_id
		 WHERE `+where+`
		 ORDER BY
		   CASE r.status WHEN 'in_progress' THEN 0 WHEN 'open' THEN 1 ELSE 2 END,
		   CASE COALESCE(f.severity,'') WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'INFO' THEN 4 WHEN 'LOW' THEN 5 ELSE 6 END,
		   r.updated_at DESC
		 LIMIT 200`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Remediation
	for rows.Next() {
		var r Remediation
		_ = rows.Scan(&r.ID, &r.FindingID, &r.TenantID, &r.Status,
			&r.Assignee, &r.Priority, &r.DueDate, &r.Notes,
			&r.TicketURL, &r.ResolvedAt, &r.CreatedAt, &r.UpdatedAt,
			&r.Title, &r.Severity, &r.Tool, &r.RuleID) //nolint
		list = append(list, r)
	}
	return list, nil
}

func (db *DB) AddComment(ctx context.Context, remID, author, body string) (*RemediationComment, error) {
	if len(body) > 10000 {
		body = body[:10000]
	} // cap comment length
	if len(author) > 200 {
		author = author[:200]
	}
	row := db.pool.QueryRow(ctx,
		`INSERT INTO remediation_comments (remediation_id,author,body)
		 VALUES ($1,$2,$3) RETURNING id,remediation_id,author,body,created_at`,
		remID, author, body)
	var c RemediationComment
	err := row.Scan(&c.ID, &c.RemediationID, &c.Author, &c.Body, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (db *DB) ListComments(ctx context.Context, remID string) ([]RemediationComment, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id,remediation_id,author,body,created_at
		 FROM remediation_comments WHERE remediation_id=$1 ORDER BY created_at ASC LIMIT 500`,
		remID)
	if err != nil {
		return nil, err
	}
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
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stats := map[string]int{"open": 0, "in_progress": 0, "resolved": 0, "accepted": 0, "false_positive": 0, "suppressed": 0}
	for rows.Next() {
		var s string
		var n int
		rows.Scan(&s, &n) //nolint
		stats[s] = n
	}
	var total int
	for _, v := range stats {
		total += v
	}
	if total > 0 {
		// remediation_rate as integer percent (avoids changing return type)
		stats["total"] = total
		stats["remediation_rate_pct"] = int(float64(stats["resolved"]+stats["accepted"]) / float64(total) * 100)
	} else {
		stats["total"] = 0
		stats["remediation_rate_pct"] = 0
	}
	return stats, nil
}

// BulkUpsertRemediations upsert nhiều remediations trong 1 transaction.
// Thay thế vòng lặp N×UpsertRemediation trong pipeline/worker.go.
func (db *DB) BulkUpsertRemediations(ctx context.Context, items []Remediation) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("bulk upsert remediation: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	const q = `INSERT INTO remediations (finding_id, tenant_id, status, priority)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (finding_id) DO NOTHING`

	batch := &pgx.Batch{}
	for _, r := range items {
		batch.Queue(q, r.FindingID, r.TenantID, r.Status, r.Priority)
	}

	results := tx.SendBatch(ctx, batch)
	for range items {
		if _, err := results.Exec(); err != nil {
			results.Close()
			return fmt.Errorf("bulk upsert remediation exec: %w", err)
		}
	}
	if err := results.Close(); err != nil {
		return fmt.Errorf("bulk upsert remediation close: %w", err)
	}
	return tx.Commit(ctx)
}

// UpdateRemediationFields applies a partial update to a remediation row.
// Only the keys present in `fields` are written to SQL — zero-value defaults
// for omitted keys do NOT clobber existing data. Used by PATCH endpoints
// where clients send only the fields they want to change.
//
// Allowed columns are whitelisted to prevent SQL injection via field name.
// resolved_at is auto-set when status transitions to a terminal value.
func (db *DB) UpdateRemediationFields(ctx context.Context, findingID, tenantID string, fields map[string]any) (*Remediation, error) {
	if len(fields) == 0 {
		return nil, fmt.Errorf("no fields to update")
	}

	allowed := map[string]bool{
		"status": true, "assignee": true, "priority": true,
		"notes": true, "ticket_url": true, "due_date": true,
	}

	setParts := []string{"updated_at = NOW()"}
	args := []any{findingID, tenantID}
	i := 3

	for col, val := range fields {
		if !allowed[col] {
			continue
		}
		setParts = append(setParts, fmt.Sprintf("%s=$%d", col, i))
		args = append(args, val)
		i++
	}

	if len(setParts) == 1 { // only updated_at — no real fields after whitelist
		return nil, fmt.Errorf("no allowed fields to update")
	}

	q := fmt.Sprintf(`
		UPDATE remediations 
		SET %s,
		    resolved_at = CASE 
		        WHEN status IN ('resolved','false_positive') AND resolved_at IS NULL THEN NOW()
		        ELSE resolved_at 
		    END
		WHERE finding_id=$1::uuid AND tenant_id=$2::uuid
		RETURNING id, finding_id, tenant_id, status, assignee, priority, due_date,
		          notes, ticket_url, resolved_at, created_at, updated_at`,
		strings.Join(setParts, ", "))

	var out Remediation
	err := db.pool.QueryRow(ctx, q, args...).Scan(
		&out.ID, &out.FindingID, &out.TenantID, &out.Status,
		&out.Assignee, &out.Priority, &out.DueDate, &out.Notes,
		&out.TicketURL, &out.ResolvedAt, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("remediation not found for finding_id=%s", findingID)
		}
		return nil, fmt.Errorf("partial update remediation: %w", err)
	}
	return &out, nil
}

// ════════════════════════════════════════════════════════════════════
// Phase 1 — History audit + KPIs (added 2026-05-04)
// ════════════════════════════════════════════════════════════════════

// RemediationHistoryEntry — audit row
type RemediationHistoryEntry struct {
	ID        int64     `json:"id"`
	RemID     string    `json:"rem_id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	FromValue string    `json:"from"`
	ToValue   string    `json:"to"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// WriteRemediationHistory — insert audit row.
// remID phải là remediations.id (UUID), không phải finding_id.
func (db *DB) WriteRemediationHistory(ctx context.Context, remID, actor, action, fromV, toV, note string) error {
	if remID == "" {
		return fmt.Errorf("rem_id required")
	}
	if len(actor) > 200 {
		actor = actor[:200]
	}
	if len(note) > 5000 {
		note = note[:5000]
	}
	_, err := db.pool.Exec(ctx, `
		INSERT INTO remediation_history(rem_id, actor, action, from_value, to_value, note)
		VALUES ($1,$2,$3,$4,$5,$6)
	`, remID, actor, action, fromV, toV, note)
	return err
}

// ListRemediationHistory — return audit rows for a remediation, newest first.
func (db *DB) ListRemediationHistory(ctx context.Context, remID string, limit int) ([]RemediationHistoryEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := db.pool.Query(ctx, `
		SELECT id, rem_id, actor, action, from_value, to_value, note, created_at
		FROM remediation_history
		WHERE rem_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, remID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []RemediationHistoryEntry{}
	for rows.Next() {
		var e RemediationHistoryEntry
		if err := rows.Scan(&e.ID, &e.RemID, &e.Actor, &e.Action,
			&e.FromValue, &e.ToValue, &e.Note, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountOverdueRemediations — items có sla_due quá hạn và còn open/in_progress.
func (db *DB) CountOverdueRemediations(ctx context.Context, tenantID string) (int, error) {
	var n int
	err := db.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM remediations
		WHERE tenant_id = $1
		  AND status IN ('open','in_progress')
		  AND sla_due IS NOT NULL AND sla_due < NOW()
	`, tenantID).Scan(&n)
	return n, err
}
