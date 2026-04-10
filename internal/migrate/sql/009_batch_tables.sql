-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS batch_runs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id    TEXT NOT NULL UNIQUE,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    label       TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'QUEUED',  -- QUEUED RUNNING DONE FAILED CANCELLED
    total       INT  NOT NULL DEFAULT 0,
    done        INT  NOT NULL DEFAULT 0,
    passed      INT  NOT NULL DEFAULT 0,
    warned      INT  NOT NULL DEFAULT 0,
    failed      INT  NOT NULL DEFAULT 0,
    parallel    INT  NOT NULL DEFAULT 3,
    fail_fast   BOOLEAN NOT NULL DEFAULT false,
    started_at  TIMESTAMPTZ,
    done_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS batch_jobs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id    TEXT NOT NULL REFERENCES batch_runs(batch_id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    idx         INT  NOT NULL DEFAULT 0,
    rid         TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL DEFAULT 'FULL',
    profile     TEXT NOT NULL DEFAULT 'FAST',
    src         TEXT NOT NULL DEFAULT '',
    label       TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'QUEUED',
    gate        TEXT NOT NULL DEFAULT '—',
    findings    INT  NOT NULL DEFAULT 0,
    error       TEXT NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ,
    done_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_batch_runs_tenant    ON batch_runs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_batch_runs_status    ON batch_runs(status);
CREATE INDEX IF NOT EXISTS idx_batch_jobs_batch_id  ON batch_jobs(batch_id);
CREATE INDEX IF NOT EXISTS idx_batch_jobs_tenant    ON batch_jobs(tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS batch_jobs;
DROP TABLE IF EXISTS batch_runs;
-- +goose StatementEnd
