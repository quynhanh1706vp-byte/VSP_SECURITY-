-- +goose Up
-- +goose StatementBegin

-- ════════════════════════════════════════════════════════════════════
-- Endpoint Agents — track installed VSP agents on assets, software
-- inventory snapshots, and submission audit log.
--
-- Schema differences from the original draft (docs/migrations-drafts/
-- 20260504_001_agents.sql): added tenant_id UUID NOT NULL on all three
-- tables to align with the platform's multi-tenant model. Switched ids
-- from VARCHAR(40) to UUID for consistency with the rest of the schema.
-- ════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS agents (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL,
    hostname      TEXT NOT NULL,
    os_family     TEXT,                              -- linux | windows | darwin
    os_version    TEXT,
    arch          TEXT,                              -- x86_64 | arm64
    asset_id      UUID,                              -- FK to assets when matched (no FK constraint to allow soft linking)
    api_key_hash  TEXT NOT NULL,                     -- sha256 of API key (never store plaintext)
    api_key_hint  TEXT,                              -- last 4 chars for UI display
    enrolled_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ,
    last_ip       INET,
    status        TEXT NOT NULL DEFAULT 'active',    -- active | revoked | stale
    version       TEXT,                              -- agent version
    UNIQUE(api_key_hash)
);

CREATE INDEX IF NOT EXISTS idx_agents_tenant   ON agents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents(tenant_id, hostname);
CREATE INDEX IF NOT EXISTS idx_agents_status   ON agents(tenant_id, status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_agents_seen     ON agents(tenant_id, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS software_packages (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    agent_id      UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    version       TEXT,
    package_mgr   TEXT,                              -- dpkg | rpm | brew | choco | msi
    architecture  TEXT,
    install_date  TIMESTAMPTZ,
    reported_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cve_matched   TEXT[],                            -- populated by background job
    UNIQUE(agent_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_pkg_tenant      ON software_packages(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pkg_agent       ON software_packages(agent_id);
CREATE INDEX IF NOT EXISTS idx_pkg_name        ON software_packages(tenant_id, name, version);
CREATE INDEX IF NOT EXISTS idx_pkg_cve         ON software_packages USING GIN(cve_matched);

CREATE TABLE IF NOT EXISTS inventory_reports (
    id             BIGSERIAL PRIMARY KEY,
    tenant_id      UUID NOT NULL,
    agent_id       UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    package_count  INT,
    bytes          INT,
    source_ip      INET,
    user_agent     TEXT
);

CREATE INDEX IF NOT EXISTS idx_invrep_tenant     ON inventory_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invrep_agent_time ON inventory_reports(agent_id, received_at DESC);

COMMENT ON TABLE agents IS 'Endpoint agents enrolled to a tenant. api_key_hash is sha256(api_key); api_key_hint is the last 4 chars for UI display only.';
COMMENT ON TABLE software_packages IS 'Per-agent software inventory snapshot. Latest snapshot replaces prior via UPSERT on (agent_id, name, version).';
COMMENT ON TABLE inventory_reports IS 'Audit log of inventory submissions for billing and rate-limit tracking.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS inventory_reports CASCADE;
DROP TABLE IF EXISTS software_packages CASCADE;
DROP TABLE IF EXISTS agents CASCADE;
-- +goose StatementEnd
