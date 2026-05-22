package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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
	// L5 2026-05-09: this used to be a naive INSERT-then-UPDATE pattern
	// that briefly wrote hash='pending' between statements. Any concurrent
	// caller that entered InsertAudit during that window would call
	// GetLastAuditHash and read 'pending' as the previous tip — when its
	// own UPDATE then committed, the chain was broken (verify reports
	// "prev_hash mismatch at seq N"). Real prod break observed at seq 1932.
	//
	// Fix: serialize per-tenant via pg_advisory_xact_lock. The lock is
	// scoped to the transaction, auto-released on commit/rollback, and
	// gives us atomic "read tip → insert chained row → write final hash"
	// semantics without a schema change. Per-tenant key keeps cross-
	// tenant writes parallel.
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return 0, "", fmt.Errorf("audit tx begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Use the high 32 bits of an md5 over tenant_id as the lock key.
	// hashtext() is built into Postgres and good enough — the key only
	// has to be stable per tenant; collisions just mean two tenants
	// briefly serialize, not a correctness issue.
	if _, err = tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('vsp_audit_chain_'||$1)::bigint)`,
		p.TenantID); err != nil {
		return 0, "", fmt.Errorf("audit advisory lock: %w", err)
	}

	// Re-read the tip INSIDE the lock so the prev_hash we chain off is
	// guaranteed to be the finalized hash of the previous row.
	var tipHash string
	err = tx.QueryRow(ctx,
		`SELECT COALESCE(hash,'') FROM audit_log
		 WHERE tenant_id=$1 ORDER BY seq DESC LIMIT 1`,
		p.TenantID).Scan(&tipHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, "", fmt.Errorf("audit re-read tip: %w", err)
	}
	// Caller passed a hint; trust the in-tx read over it.
	prevHash := tipHash

	var seq int64
	err = tx.QueryRow(ctx,
		`INSERT INTO audit_log (tenant_id, user_id, action, resource, ip, payload, hash, prev_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,'pending',$7)
		 RETURNING seq`,
		p.TenantID, p.UserID, p.Action, p.Resource, p.IP, p.Payload, prevHash,
	).Scan(&seq)
	if err != nil {
		return 0, "", fmt.Errorf("insert audit: %w", err)
	}
	h := audit.Hash(audit.Entry{
		Seq: seq, TenantID: p.TenantID,
		Action: p.Action, Resource: p.Resource, PrevHash: prevHash,
	})
	if _, err = tx.Exec(ctx,
		`UPDATE audit_log SET hash=$1 WHERE seq=$2`, h, seq); err != nil {
		return seq, h, fmt.Errorf("update audit hash: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return seq, h, fmt.Errorf("audit tx commit: %w", err)
	}
	return seq, h, nil
}

func (db *DB) GetLastAuditHash(ctx context.Context, tenantID string) (string, error) {
	var hash string
	// L5 2026-05-09 defense in depth: skip 'pending' rows (a transient
	// state another writer is mid-finalising). The advisory-lock fix in
	// InsertAudit makes this filter mostly redundant, but callers that
	// pre-read prev_hash before InsertAudit (e.g. handlers that compute
	// the hash themselves for Entry.StoredHash) still benefit.
	err := db.pool.QueryRow(ctx,
		`SELECT hash FROM audit_log
		   WHERE tenant_id=$1 AND hash <> 'pending'
		   ORDER BY seq DESC LIMIT 1`,
		tenantID).Scan(&hash)
	if err != nil {
		// First audit entry for this tenant — no rows is expected, not
		// an error. Any other DB error gets surfaced so callers can
		// log / fail rather than silently chain off an empty hash.
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("get last audit hash: %w", err)
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

// UpdateAuditHashes rewrites the hash + prev_hash for a contiguous tail of
// audit entries (typically after a chain integrity break). Transactional —
// either all updates land or none. Implements the audit.Repairer interface.
//
// The caller (audit.RepairChain) is responsible for ensuring the rebuilt
// hashes form a valid chain and for writing a follow-up CHAIN_REPAIRED audit
// entry recording who triggered the repair.
func (db *DB) UpdateAuditHashes(ctx context.Context, tenantID string, entries []audit.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("repair: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, e := range entries {
		// Defense in depth: only update rows belonging to the requesting tenant
		// to prevent cross-tenant tampering even if a bug routed a wrong list.
		_, err := tx.Exec(ctx,
			`UPDATE audit_log SET hash=$1, prev_hash=$2
			 WHERE seq=$3 AND tenant_id=$4`,
			e.StoredHash, e.PrevHash, e.Seq, tenantID)
		if err != nil {
			return fmt.Errorf("repair: update seq %d: %w", e.Seq, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("repair: commit: %w", err)
	}
	return nil
}

// ListAuditPagedFiltered — like ListAuditPaged but with from/to date filters.
func (db *DB) ListAuditPagedFiltered(ctx context.Context, tenantID, actionFilter, fromFilter, toFilter string, limit, offset int) ([]AuditEntry, int64, error) {
	if limit <= 0 || limit > 1000 { limit = 50 }
	base := " WHERE tenant_id = $1"
	args := []any{tenantID}
	i := 2
	if actionFilter != "" {
		base += fmt.Sprintf(" AND action ILIKE $%d", i)
		args = append(args, "%"+actionFilter+"%")
		i++
	}
	if fromFilter != "" {
		base += fmt.Sprintf(" AND created_at >= $%d", i)
		args = append(args, fromFilter)
		i++
	}
	if toFilter != "" {
		base += fmt.Sprintf(" AND created_at <= $%d", i)
		args = append(args, toFilter+" 23:59:59")
		i++
	}
	var total int64
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	_ = db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM audit_log"+base, countArgs...).Scan(&total)
	args = append(args, limit, offset)
	rows, err := db.pool.Query(ctx,
		"SELECT seq, action, COALESCE(resource,''), COALESCE(ip,''), created_at"+
		" FROM audit_log"+base+
		fmt.Sprintf(" ORDER BY seq DESC LIMIT $%d OFFSET $%d", i, i+1),
		args...)
	if err != nil { return nil, 0, err }
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Seq, &e.Action, &e.Resource, &e.IP, &e.CreatedAt); err == nil {
			out = append(out, e)
		}
	}
	return out, total, nil
}
