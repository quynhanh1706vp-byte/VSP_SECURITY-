-- +goose Up
-- +goose StatementBegin

-- Index supporting per-fingerprint MIN(created_at) / MAX(created_at)
-- correlated subqueries in store.ListFindings. Required by FE Finding
-- detail modal (vsp_upgrade_v100.js:3209,3210) which renders
-- "First seen" / "Last seen" rows. Before this index they were "—"
-- because the BE struct didn't carry them at all — adding the columns
-- alone (computed on-read) was free given the fingerprint dedup index
-- from migration 011, but a (tenant_id, fingerprint) index is needed
-- so the correlated subquery is constant-time per row instead of a
-- full findings table scan per row in the result set.

CREATE INDEX IF NOT EXISTS idx_findings_tenant_fp
    ON findings(tenant_id, fingerprint);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_findings_tenant_fp;

-- +goose StatementEnd
