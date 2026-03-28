-- name: CreateAPIKey :one
INSERT INTO api_keys (tenant_id, label, prefix, hash, role, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetAPIKeyByPrefix :one
SELECT * FROM api_keys
WHERE prefix = $1 AND tenant_id = $2
LIMIT 1;

-- name: ListAPIKeys :many
SELECT id, tenant_id, label, prefix, role, expires_at, last_used, use_count, created_at
FROM api_keys
WHERE tenant_id = $1
ORDER BY created_at DESC;

-- name: DeleteAPIKey :exec
DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2;

-- name: TouchAPIKey :exec
UPDATE api_keys
SET last_used = NOW(), use_count = use_count + 1
WHERE id = $1;
