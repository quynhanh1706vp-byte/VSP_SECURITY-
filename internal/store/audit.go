package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vsp/platform/internal/audit"
)

type AuditEntry struct {
	Seq       int64           `json:"seq"`
	TenantID  string          `json:"tenant_id"`
	UserID    *string         `json:"user_id"`
	Action    string          `json:"action"`
	Resource  string          `json:"resource"`
	IP        string          `json:"ip"`
	Payload   json.RawMessage `json:"payload"`
	Hash      string          `json:"hash"`
	PrevHash  string          `json:"prev_hash"`
	CreatedAt time.Time       `json:"created_at"`
}

func (db *DB) InsertAudit(ctx context.Context, p AuditWriteParams) (int64, string, error) {
	var seq int64
	err := db.pool.QueryRow(ctx,
		`INSERT INTO audit_log (tenant_id, user_id, action, resource, ip, payload, hash, prev_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,'pending',$7)
		 RETURNING seq`,
		p.TenantID, p.UserID, p.Action, p.Resource, p.IP, p.Payload, p.PrevHash,
	).Scan(&seq)
	if err != nil {
		return 0, "", fmt.Errorf("insert audit: %w", err)
	}
	h := audit.Hash(audit.Entry{
		Seq: seq, TenantID: p.TenantID,
		Action: p.Action, Resource: p.Resource, PrevHash: p.PrevHash,
	})
	if _, err = db.pool.Exec(ctx,
		`UPDATE audit_log SET hash=$1 WHERE seq=$2`, h, seq); err != nil {
		return seq, h, fmt.Errorf("update audit hash: %w", err)
	}
	return seq, h, nil
}

func (db *DB) GetLastAuditHash(ctx context.Context, tenantID string) (string, error) {
	var hash string
	err := db.pool.QueryRow(ctx,
		`SELECT hash FROM audit_log WHERE tenant_id=$1 ORDER BY seq DESC LIMIT 1`,
		tenantID).Scan(&hash)
	if err != nil {
		return "", nil
	}
	return hash, nil
}

func (db *DB) ListAuditPaged(ctx context.Context, tenantID, actionFilter string, limit, offset int) ([]AuditEntry, int64, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT seq, tenant_id, user_id, action, resource, ip, hash, prev_hash, created_at
		 FROM audit_log
		 WHERE tenant_id=$1 AND ($2='' OR action=$2)
		 ORDER BY seq DESC LIMIT $3 OFFSET $4`,
		tenantID, actionFilter, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Seq, &e.TenantID, &e.UserID, &e.Action,
			&e.Resource, &e.IP, &e.Hash, &e.PrevHash, &e.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan audit row: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate audit rows: %w", err)
	}
	var count int64
	if err := db.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE tenant_id=$1`, tenantID).Scan(&count); err != nil {
		return entries, 0, fmt.Errorf("count audit: %w", err)
	}
	return entries, count, nil
}

func (db *DB) ListAuditByTenant(ctx context.Context, tenantID string) ([]AuditEntry, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT seq, tenant_id, user_id, action, resource, ip, hash, prev_hash, created_at
		 FROM audit_log WHERE tenant_id=$1 ORDER BY seq ASC LIMIT 10000`,
		tenantID)
	if err != nil {
		return nil, fmt.Errorf("list audit by tenant: %w", err)
	}
	defer rows.Close()
	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Seq, &e.TenantID, &e.UserID, &e.Action,
			&e.Resource, &e.IP, &e.Hash, &e.PrevHash, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
