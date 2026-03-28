-- name: InsertAudit :one
INSERT INTO audit_log (tenant_id, user_id, action, resource, ip, payload, hash, prev_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING seq, hash;

-- name: ListAuditByTenant :many
SELECT seq, tenant_id, user_id, action, resource, ip, hash, prev_hash, created_at
FROM audit_log
WHERE tenant_id = $1
ORDER BY seq ASC;

-- name: GetLastAuditHash :one
SELECT hash FROM audit_log
WHERE tenant_id = $1
ORDER BY seq DESC
LIMIT 1;

-- name: ListAuditPaged :many
SELECT seq, tenant_id, user_id, action, resource, ip, hash, prev_hash, created_at
FROM audit_log
WHERE tenant_id = $1
  AND ($2::text = '' OR action = $2)
ORDER BY seq DESC
LIMIT $3 OFFSET $4;

-- name: CountAudit :one
SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1;
