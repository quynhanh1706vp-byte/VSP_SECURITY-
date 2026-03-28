-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE tenants (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug       TEXT UNIQUE NOT NULL,
  name       TEXT NOT NULL,
  plan       TEXT NOT NULL DEFAULT 'starter',
  active     BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email       TEXT NOT NULL,
  pw_hash     TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'analyst',
  mfa_enabled BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login  TIMESTAMPTZ,
  UNIQUE(tenant_id, email)
);

CREATE TABLE api_keys (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID NOT NULL REFERENCES tenants(id),
  label      TEXT NOT NULL,
  prefix     TEXT NOT NULL,
  hash       TEXT NOT NULL,
  role       TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  last_used  TIMESTAMPTZ,
  use_count  INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE runs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rid          TEXT UNIQUE NOT NULL,
  tenant_id    UUID NOT NULL REFERENCES tenants(id),
  mode         TEXT NOT NULL,
  profile      TEXT NOT NULL DEFAULT 'FAST',
  src          TEXT,
  target_url   TEXT,
  status       TEXT NOT NULL DEFAULT 'QUEUED',
  gate         TEXT,
  posture      TEXT,
  tools_done   INT NOT NULL DEFAULT 0,
  tools_total  INT NOT NULL DEFAULT 8,
  total_findings INT NOT NULL DEFAULT 0,
  summary      JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at   TIMESTAMPTZ,
  finished_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_runs_tenant   ON runs(tenant_id, created_at DESC);
CREATE INDEX idx_runs_status   ON runs(tenant_id, status);

CREATE TABLE findings (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id     UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  tenant_id  UUID NOT NULL,
  tool       TEXT NOT NULL,
  severity   TEXT NOT NULL,
  rule_id    TEXT,
  message    TEXT,
  path       TEXT,
  line_num   INT,
  cwe        TEXT,
  fix_signal TEXT,
  raw        JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_run      ON findings(run_id);
CREATE INDEX idx_findings_severity ON findings(tenant_id, severity);
CREATE INDEX idx_findings_tool     ON findings(tenant_id, tool);

CREATE TABLE audit_log (
  seq        BIGSERIAL PRIMARY KEY,
  tenant_id  UUID NOT NULL,
  user_id    UUID,
  action     TEXT NOT NULL,
  resource   TEXT,
  ip         TEXT,
  payload    JSONB,
  hash       TEXT NOT NULL,
  prev_hash  TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant ON audit_log(tenant_id, seq);

CREATE TABLE siem_webhooks (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  label       TEXT NOT NULL,
  type        TEXT NOT NULL,
  url         TEXT NOT NULL,
  secret_hash TEXT,
  min_sev     TEXT NOT NULL DEFAULT 'HIGH',
  active      BOOLEAN NOT NULL DEFAULT true,
  last_fired  TIMESTAMPTZ,
  fire_count  INT NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE policy_rules (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL REFERENCES tenants(id),
  name           TEXT NOT NULL,
  repo_pattern   TEXT NOT NULL DEFAULT '*',
  fail_on        TEXT NOT NULL DEFAULT 'FAIL',
  min_score      INT DEFAULT 0,
  max_high       INT DEFAULT -1,
  block_secrets  BOOLEAN NOT NULL DEFAULT true,
  block_critical BOOLEAN NOT NULL DEFAULT true,
  active         BOOLEAN NOT NULL DEFAULT true,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default tenant for dev
INSERT INTO tenants (slug, name, plan) VALUES ('default', 'Default Tenant', 'enterprise');

-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS policy_rules;
DROP TABLE IF EXISTS siem_webhooks;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;
