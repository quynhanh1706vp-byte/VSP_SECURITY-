-- 021_secret_vault_config.sql — per-tenant config for the PRO Secret Vault feature.
-- Stores rotation policy + retention so the "view details" panel can render
-- and edit the tenant's vault settings.

CREATE TABLE IF NOT EXISTS secret_vault_config (
    tenant_id          UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    rotation_days      INT  NOT NULL DEFAULT 90  CHECK (rotation_days BETWEEN 1 AND 730),
    audit_retention_d  INT  NOT NULL DEFAULT 365 CHECK (audit_retention_d BETWEEN 7 AND 2555),
    require_approval   BOOL NOT NULL DEFAULT FALSE,
    allowed_providers  TEXT NOT NULL DEFAULT 'internal',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
