-- migrations/XXXXXX_siem_tables.sql
-- VSP SIEM — Correlation · Playbooks · Log sources · IOCs

-- ── Correlation rules ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS correlation_rules (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL,
    name           TEXT        NOT NULL,
    sources        TEXT[]      DEFAULT '{}',
    window_min     INT         DEFAULT 5,
    severity       TEXT        DEFAULT 'HIGH',
    condition_expr TEXT        DEFAULT '',
    enabled        BOOL        DEFAULT true,
    hits           INT         DEFAULT 0,
    created_at     TIMESTAMPTZ DEFAULT NOW(),
    updated_at     TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_correlation_rules_tenant ON correlation_rules(tenant_id);

-- ── Incidents ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL,
    rule_id     UUID        REFERENCES correlation_rules(id) ON DELETE SET NULL,
    title       TEXT        NOT NULL,
    severity    TEXT        DEFAULT 'HIGH',
    status      TEXT        DEFAULT 'open',
    source_refs JSONB       DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant   ON incidents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(tenant_id, severity);

-- ── SOAR playbooks ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS playbooks (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL,
    name          TEXT        NOT NULL,
    description   TEXT        DEFAULT '',
    trigger_event TEXT        DEFAULT 'manual',
    sev_filter    TEXT        DEFAULT 'any',
    steps         JSONB       DEFAULT '[]',
    enabled       BOOL        DEFAULT true,
    run_count     INT         DEFAULT 0,
    success_count INT         DEFAULT 0,
    last_run_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_playbooks_tenant  ON playbooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_playbooks_trigger ON playbooks(tenant_id, trigger_event, enabled);

-- ── Playbook run history ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS playbook_runs (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id   UUID        REFERENCES playbooks(id) ON DELETE CASCADE,
    tenant_id     UUID        NOT NULL,
    status        TEXT        DEFAULT 'running',
    trigger_event TEXT        DEFAULT 'manual',
    context       JSONB       DEFAULT '{}',
    log           JSONB       DEFAULT '[]',
    duration_s    INT,
    started_at    TIMESTAMPTZ DEFAULT NOW(),
    finished_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_pb     ON playbook_runs(playbook_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_tenant ON playbook_runs(tenant_id, started_at DESC);

-- ── Log sources ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS log_sources (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL,
    name        TEXT        NOT NULL,
    host        TEXT        DEFAULT '',
    protocol    TEXT        DEFAULT 'syslog-udp',
    port        INT         DEFAULT 514,
    format      TEXT        DEFAULT 'syslog-rfc3164',
    tags        TEXT[]      DEFAULT '{}',
    enabled     BOOL        DEFAULT true,
    eps         INT         DEFAULT 0,
    parse_rate  FLOAT       DEFAULT 0,
    status      TEXT        DEFAULT 'idle',
    last_seen   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_log_sources_tenant ON log_sources(tenant_id);

-- ── IOC / Threat intel cache ──────────────────────────────────
CREATE TABLE IF NOT EXISTS iocs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    type        TEXT        NOT NULL,  -- cve | hash | ip | domain
    value       TEXT        NOT NULL,
    severity    TEXT        DEFAULT 'MEDIUM',
    feed        TEXT        DEFAULT 'manual',
    description TEXT        DEFAULT '',
    meta        JSONB       DEFAULT '{}',
    matched     BOOL        DEFAULT false,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_value  ON iocs(value);
CREATE        INDEX IF NOT EXISTS idx_iocs_type   ON iocs(type, severity);
CREATE        INDEX IF NOT EXISTS idx_iocs_matched ON iocs(matched) WHERE matched=true;

-- ── Seed default correlation rules ───────────────────────────
-- (chạy sau khi có tenant_id, bỏ qua nếu đã có)
-- INSERT INTO correlation_rules (tenant_id, name, sources, window_min, severity, condition_expr, enabled)
-- VALUES
--   ('<tenant_id>', 'Gate FAIL + secrets in window', ARRAY['scan','git'], 5, 'CRITICAL', 'gate=FAIL AND tool=gitleaks', true),
--   ('<tenant_id>', 'CVE critical + deploy event',   ARRAY['scan','infra'], 10, 'CRITICAL', 'severity=CRITICAL AND event=deploy', true),
--   ('<tenant_id>', 'SLA breach + no assignee',      ARRAY['sla','remediation'], 1440, 'MEDIUM', 'sla.status=breach AND assignee=null', true);
