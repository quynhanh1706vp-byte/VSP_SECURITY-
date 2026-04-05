-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS correlation_rules (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    sources        TEXT[] NOT NULL DEFAULT '{}',
    window_min     INT NOT NULL DEFAULT 5,
    severity       TEXT NOT NULL DEFAULT 'HIGH',
    condition_expr TEXT NOT NULL DEFAULT '',
    enabled        BOOLEAN NOT NULL DEFAULT true,
    hits           INT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id     UUID REFERENCES correlation_rules(id) ON DELETE SET NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'HIGH',
    status      TEXT NOT NULL DEFAULT 'open',
    source_refs JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS playbooks (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    trigger_event TEXT NOT NULL DEFAULT 'incident_created',
    sev_filter    TEXT NOT NULL DEFAULT 'any',
    steps         JSONB NOT NULL DEFAULT '[]',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    run_count     INT NOT NULL DEFAULT 0,
    success_count INT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS playbook_runs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    trigger_event TEXT NOT NULL DEFAULT '',
    context     JSONB NOT NULL DEFAULT '{}',
    duration_s  INT,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS log_sources (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    host       TEXT NOT NULL DEFAULT '',
    protocol   TEXT NOT NULL DEFAULT 'syslog',
    port       INT NOT NULL DEFAULT 514,
    format     TEXT NOT NULL DEFAULT 'rfc5424',
    tags       TEXT[] NOT NULL DEFAULT '{}',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    eps        INT NOT NULL DEFAULT 0,
    parse_rate FLOAT NOT NULL DEFAULT 0,
    status     TEXT NOT NULL DEFAULT 'unknown',
    last_seen  TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS log_events (
    id        BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    source_id UUID REFERENCES log_sources(id) ON DELETE SET NULL,
    host      TEXT,
    facility  TEXT,
    severity  TEXT,
    process   TEXT,
    message   TEXT,
    fields    JSONB NOT NULL DEFAULT '{}',
    ts        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS iocs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL UNIQUE,
    severity    TEXT NOT NULL DEFAULT 'MEDIUM',
    feed        TEXT NOT NULL DEFAULT 'manual',
    description TEXT NOT NULL DEFAULT '',
    matched     BOOLEAN NOT NULL DEFAULT false,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS remediations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  UUID NOT NULL UNIQUE,
    tenant_id   UUID NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    assignee    TEXT NOT NULL DEFAULT '',
    priority    TEXT NOT NULL DEFAULT 'P3',
    due_date    TIMESTAMPTZ,
    notes       TEXT NOT NULL DEFAULT '',
    ticket_url  TEXT NOT NULL DEFAULT '',
    resolved_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS remediation_comments (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    remediation_id UUID NOT NULL REFERENCES remediations(id) ON DELETE CASCADE,
    author         TEXT NOT NULL,
    body           TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rem_finding ON remediations(finding_id);
CREATE INDEX IF NOT EXISTS idx_rem_tenant  ON remediations(tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS remediation_comments;
DROP TABLE IF EXISTS remediations;
DROP TABLE IF EXISTS iocs;
DROP TABLE IF EXISTS log_events;
DROP TABLE IF EXISTS log_sources;
DROP TABLE IF EXISTS playbook_runs;
DROP TABLE IF EXISTS playbooks;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS correlation_rules;
-- +goose StatementEnd
