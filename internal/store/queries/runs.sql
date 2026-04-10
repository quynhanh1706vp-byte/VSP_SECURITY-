-- name: CreateRun :one
INSERT INTO runs (rid, tenant_id, mode, profile, src, target_url, tools_total)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetRunByRID :one
SELECT * FROM runs WHERE rid = $1 AND tenant_id = $2 LIMIT 1;

-- name: GetLatestRun :one
-- Note: Go implementation filters status='DONE' AND total_findings > 0
-- This raw SQL is for reference only — use store.DB.GetLatestRun() instead
SELECT * FROM runs
WHERE tenant_id = $1
  AND status = 'DONE'
ORDER BY created_at DESC
LIMIT 1;

-- name: ListRuns :many
SELECT * FROM runs
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: UpdateRunStatus :exec
UPDATE runs
SET status = $3, tools_done = $4, started_at = CASE WHEN $3 = 'RUNNING' THEN NOW() ELSE started_at END,
    finished_at = CASE WHEN $3 IN ('DONE','FAILED','CANCELLED') THEN NOW() ELSE finished_at END
WHERE rid = $1 AND tenant_id = $2;

-- name: UpdateRunResult :exec
UPDATE runs
SET status = 'DONE', gate = $3, posture = $4,
    total_findings = $5, summary = $6,
    tools_done = tools_total, finished_at = NOW()
WHERE rid = $1 AND tenant_id = $2;

-- name: CancelRun :exec
UPDATE runs
SET status = 'CANCELLED', finished_at = NOW()
WHERE rid = $1 AND tenant_id = $2 AND status IN ('QUEUED','RUNNING');
