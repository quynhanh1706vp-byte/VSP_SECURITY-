-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS scan_schedules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    name        TEXT NOT NULL,
    mode        TEXT NOT NULL DEFAULT 'SAST',
    profile     TEXT NOT NULL DEFAULT 'FAST',
    src         TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL DEFAULT '',
    cron_expr   TEXT NOT NULL DEFAULT '0 2 * * *',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS drift_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL,
    schedule_id  UUID,
    prev_posture TEXT NOT NULL DEFAULT '',
    new_posture  TEXT NOT NULL DEFAULT '',
    prev_score   INT NOT NULL DEFAULT 0,
    new_score    INT NOT NULL DEFAULT 0,
    delta        INT NOT NULL DEFAULT 0,
    rid          TEXT NOT NULL DEFAULT '',
    detected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_schedules_tenant ON scan_schedules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_drift_tenant     ON drift_events(tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS drift_events;
DROP TABLE IF EXISTS scan_schedules;
-- +goose StatementEnd
