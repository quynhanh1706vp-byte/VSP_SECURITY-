-- 020_cspm_tables.sql — Cloud Security Posture Management persistence
-- Adds two tenant-scoped tables for the PRO "Cloud posture" feature so
-- the /api/v1/cspm/* endpoints can serve real data instead of in-memory mocks.

CREATE TABLE IF NOT EXISTS cspm_accounts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider      TEXT NOT NULL CHECK (provider IN ('aws','gcp','azure','kubernetes','other')),
    name          TEXT NOT NULL,
    external_id   TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','active','disabled','error')),
    last_sync_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, provider, external_id)
);

CREATE INDEX IF NOT EXISTS cspm_accounts_tenant_idx
    ON cspm_accounts(tenant_id, status);

CREATE TABLE IF NOT EXISTS cspm_findings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    account_id   UUID NOT NULL REFERENCES cspm_accounts(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    resource     TEXT NOT NULL,
    rule_id      TEXT NOT NULL,
    rule_name    TEXT,
    message      TEXT NOT NULL,
    file         TEXT,
    status       TEXT NOT NULL DEFAULT 'open'
                 CHECK (status IN ('open','suppressed','resolved')),
    detected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS cspm_findings_tenant_severity_idx
    ON cspm_findings(tenant_id, severity, status);
CREATE INDEX IF NOT EXISTS cspm_findings_account_idx
    ON cspm_findings(account_id, detected_at DESC);

-- Per-tenant CSPM feature config: sync schedule, retention, autofix toggle.
-- Stored as a single row per tenant, upserted by the config endpoint.
CREATE TABLE IF NOT EXISTS cspm_config (
    tenant_id         UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    sync_interval_min INT  NOT NULL DEFAULT 60 CHECK (sync_interval_min BETWEEN 5 AND 1440),
    retention_days    INT  NOT NULL DEFAULT 90 CHECK (retention_days BETWEEN 7 AND 730),
    auto_fix_enabled  BOOL NOT NULL DEFAULT FALSE,
    notify_severities TEXT NOT NULL DEFAULT 'critical,high',
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
