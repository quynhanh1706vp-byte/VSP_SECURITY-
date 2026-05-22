-- 023_pro_panel_configs.sql — per-tenant config rows for the remaining 4
-- PRO sidebar panels (PR/repo bot, Supply chain, SBOM diff, SSO/SAML).
-- One table per panel because validation rules + columns differ.

CREATE TABLE IF NOT EXISTS autofix_config (
    tenant_id        UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    auto_pr_enabled  BOOL NOT NULL DEFAULT TRUE,
    sla_hours        INT  NOT NULL DEFAULT 72  CHECK (sla_hours BETWEEN 1 AND 720),
    draft_pr_only    BOOL NOT NULL DEFAULT FALSE,
    require_review   BOOL NOT NULL DEFAULT TRUE,
    max_open_prs     INT  NOT NULL DEFAULT 20  CHECK (max_open_prs BETWEEN 1 AND 500),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS supply_chain_config (
    tenant_id                  UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    verify_required            BOOL NOT NULL DEFAULT TRUE,
    slsa_min_level             INT  NOT NULL DEFAULT 2 CHECK (slsa_min_level BETWEEN 1 AND 4),
    allow_unsigned             BOOL NOT NULL DEFAULT FALSE,
    block_admission_below_min  BOOL NOT NULL DEFAULT TRUE,
    sigstore_root              TEXT NOT NULL DEFAULT 'public-good',
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sbom_config (
    tenant_id              UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    diff_alert_severity    TEXT NOT NULL DEFAULT 'high'
                           CHECK (diff_alert_severity IN ('critical','high','medium','low')),
    alert_on_new_critical  BOOL NOT NULL DEFAULT TRUE,
    sbom_format            TEXT NOT NULL DEFAULT 'cyclonedx'
                           CHECK (sbom_format IN ('cyclonedx','spdx','syft')),
    auto_generate          BOOL NOT NULL DEFAULT TRUE,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sso_config (
    tenant_id          UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    default_role       TEXT NOT NULL DEFAULT 'analyst'
                       CHECK (default_role IN ('admin','analyst','dev','auditor')),
    scim_enabled       BOOL NOT NULL DEFAULT FALSE,
    jit_provisioning   BOOL NOT NULL DEFAULT TRUE,
    require_mfa        BOOL NOT NULL DEFAULT TRUE,
    session_max_hours  INT  NOT NULL DEFAULT 8 CHECK (session_max_hours BETWEEN 1 AND 168),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
