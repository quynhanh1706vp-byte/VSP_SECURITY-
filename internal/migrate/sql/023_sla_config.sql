-- +goose Up
CREATE TABLE IF NOT EXISTS sla_config (
  tenant_id        uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  critical_days    int  NOT NULL DEFAULT 3,
  high_days        int  NOT NULL DEFAULT 14,
  medium_days      int  NOT NULL DEFAULT 30,
  low_days         int  NOT NULL DEFAULT 90,
  updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sla_config_tenant ON sla_config(tenant_id);

-- +goose Down
DROP TABLE IF EXISTS sla_config;
