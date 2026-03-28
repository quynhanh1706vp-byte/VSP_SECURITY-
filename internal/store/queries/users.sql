-- name: GetUserByEmail :one
SELECT id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login
FROM users
WHERE tenant_id = $1 AND email = $2
LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (tenant_id, email, pw_hash, role)
VALUES ($1, $2, $3, $4)
RETURNING id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login;

-- name: ListUsers :many
SELECT id, tenant_id, email, role, mfa_enabled, created_at, last_login
FROM users
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountUsers :one
SELECT COUNT(*) FROM users WHERE tenant_id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1 AND tenant_id = $2;

-- name: UpdateLastLogin :exec
UPDATE users SET last_login = NOW() WHERE id = $1;

-- name: GetUserByID :one
SELECT id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login
FROM users
WHERE id = $1 AND tenant_id = $2
LIMIT 1;
