-- 022_observability_config.sql — per-tenant observability settings exposed
-- through the PRO "Observability" sidebar feature's view-details panel.

CREATE TABLE IF NOT EXISTS observability_config (
    tenant_id                UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    alert_critical_threshold INT  NOT NULL DEFAULT 1
                             CHECK (alert_critical_threshold BETWEEN 0 AND 10000),
    alert_high_threshold     INT  NOT NULL DEFAULT 10
                             CHECK (alert_high_threshold BETWEEN 0 AND 10000),
    burn_rate_alert_enabled  BOOL NOT NULL DEFAULT TRUE,
    metrics_retention_days   INT  NOT NULL DEFAULT 30
                             CHECK (metrics_retention_days BETWEEN 1 AND 365),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
