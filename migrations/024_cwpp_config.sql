-- 024_cwpp_config.sql — per-tenant container-security policy.
-- Backs the editable Configure form on the CWPP sidebar panel.

CREATE TABLE IF NOT EXISTS cwpp_config (
    tenant_id                  UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    -- Page on-call when an image scan finds ≥ N CRITICAL CVEs.
    alert_critical_threshold   INT  NOT NULL DEFAULT 1
                               CHECK (alert_critical_threshold BETWEEN 0 AND 1000),
    -- Reject K8s admission if image has CRITICAL CVEs (cluster image policy hook).
    block_admission_on_crit    BOOL NOT NULL DEFAULT FALSE,
    -- Force re-scan of any image older than this; runs in the worker loop.
    max_scan_age_hours         INT  NOT NULL DEFAULT 24
                               CHECK (max_scan_age_hours BETWEEN 1 AND 720),
    -- Auto-scan every image referenced in a scanned manifest (admission webhook).
    scan_on_push               BOOL NOT NULL DEFAULT TRUE,
    -- Comma-separated registry globs allowed without extra signature checks.
    -- Wildcards: "registry.acme.com/**" or "ghcr.io/myorg/*".
    registry_allowlist         TEXT NOT NULL DEFAULT '',
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
