-- 026_feature_config.sql — generic per-tenant config storage for the
-- 12 SIEM panels (AI Analyst, Scheduler, Correlation, SOAR, Log Ingestion,
-- UEBA, Assets, SW Inventory, Network Flow, Threat Hunt, Vuln Mgmt,
-- Threat Intel). Each (tenant, feature_id) pair owns a JSON blob — the
-- panel's Configure form serialises into this column.
--
-- We chose JSONB over per-feature columns because:
--   1. Schemas evolve quickly; migrating 12 separate tables for every
--      sprint's new field is high friction.
--   2. The frontend already validates field shape via formModal({fields}).
--   3. Search/filter on config values is rare; key/value lookups are not.

CREATE TABLE IF NOT EXISTS feature_config (
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    feature_id  TEXT NOT NULL CHECK (feature_id IN (
        'ai_analyst', 'scheduler', 'correlation', 'soar',
        'log_ingestion', 'ueba', 'assets', 'sw_inventory',
        'network_flow', 'threat_hunt', 'vuln_mgmt', 'threat_intel'
    )),
    config      JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, feature_id)
);

CREATE INDEX IF NOT EXISTS feature_config_tenant_idx
    ON feature_config(tenant_id);
