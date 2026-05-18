-- +goose Up
-- +goose StatementBegin

-- Phase B Step 1: Per-tenant tool enable/disable configuration.
-- Tools NOT in this table = enabled by default (opt-out model).
-- pipeline.RunnersFor(mode, tenantID) will filter out tools where enabled=false.

CREATE TABLE IF NOT EXISTS tenant_tool_config (
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_name   TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    custom_args JSONB,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  UUID,
    PRIMARY KEY (tenant_id, tool_name)
);

-- Partial index: only disabled tools (most queries filter for enabled=false)
CREATE INDEX IF NOT EXISTS idx_ttc_tenant_disabled
    ON tenant_tool_config(tenant_id, tool_name)
    WHERE enabled = false;

COMMENT ON TABLE tenant_tool_config IS
    'Per-tenant scanner tool enable/disable. Absent rows = enabled (default-on opt-out model).';
COMMENT ON COLUMN tenant_tool_config.enabled IS
    'true = tool runs in pipeline; false = pipeline.RunnersFor() filters it out';
COMMENT ON COLUMN tenant_tool_config.custom_args IS
    'Optional per-tool args override (JSON object). Reserved for future use.';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_ttc_tenant_disabled;
DROP TABLE IF EXISTS tenant_tool_config;
-- +goose StatementEnd
