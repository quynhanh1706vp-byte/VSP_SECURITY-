-- +goose Up
-- +goose StatementBegin

-- ConMon (Continuous Monitoring) — FedRAMP-aligned schedule + drift
-- Phase 4.5.1 · April 2026

-- Schedules: cron-driven re-runs of pipelines per tenant
CREATE TABLE IF NOT EXISTS conmon_schedules (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    cadence         TEXT NOT NULL CHECK (cadence IN ('30d','60d','90d','daily','weekly','custom')),
    cron_expr       TEXT,
    mode            TEXT NOT NULL DEFAULT 'FULL',
    target_path     TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_run_at     TIMESTAMPTZ,
    last_run_id     BIGINT,
    last_verdict    TEXT,
    next_run_at     TIMESTAMPTZ NOT NULL,
    consecutive_pass INT NOT NULL DEFAULT 0,
    consecutive_fail INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_conmon_schedules_tenant ON conmon_schedules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_conmon_schedules_next   ON conmon_schedules(next_run_at) WHERE enabled = true;

CREATE TABLE IF NOT EXISTS conmon_deviations (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    schedule_id      BIGINT NOT NULL REFERENCES conmon_schedules(id) ON DELETE CASCADE,
    run_id           BIGINT NOT NULL,
    gate_name        TEXT NOT NULL,
    framework        TEXT NOT NULL,
    prev_verdict     TEXT NOT NULL,
    curr_verdict     TEXT NOT NULL,
    severity         TEXT NOT NULL,
    detected_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at  TIMESTAMPTZ,
    acknowledged_by  TEXT,
    poam_id          BIGINT,
    notes            TEXT
);

CREATE INDEX IF NOT EXISTS idx_conmon_dev_tenant ON conmon_deviations(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_conmon_dev_open   ON conmon_deviations(tenant_id) WHERE acknowledged_at IS NULL;

CREATE TABLE IF NOT EXISTS conmon_cadence_status (
    tenant_id       TEXT NOT NULL,
    framework       TEXT NOT NULL,
    cadence_days    INT NOT NULL,
    last_scan_at    TIMESTAMPTZ,
    next_due_at     TIMESTAMPTZ NOT NULL,
    is_overdue      BOOLEAN NOT NULL DEFAULT false,
    consecutive_met INT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, framework, cadence_days)
);

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS conmon_cadence_status;
DROP TABLE IF EXISTS conmon_deviations;
DROP TABLE IF EXISTS conmon_schedules;
-- +goose StatementEnd
