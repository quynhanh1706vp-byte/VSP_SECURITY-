-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE TABLE IF NOT EXISTS tenants (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'starter', active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, email TEXT NOT NULL, pw_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst', mfa_enabled BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_login TIMESTAMPTZ, UNIQUE(tenant_id, email));
CREATE TABLE IF NOT EXISTS api_keys (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL REFERENCES tenants(id), label TEXT NOT NULL, prefix TEXT NOT NULL, hash TEXT NOT NULL, role TEXT NOT NULL, expires_at TIMESTAMPTZ, last_used TIMESTAMPTZ, use_count INT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS runs (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), rid TEXT UNIQUE NOT NULL, tenant_id UUID NOT NULL REFERENCES tenants(id), mode TEXT NOT NULL, profile TEXT NOT NULL DEFAULT 'FAST', src TEXT, target_url TEXT, status TEXT NOT NULL DEFAULT 'QUEUED', gate TEXT, posture TEXT, tools_done INT NOT NULL DEFAULT 0, tools_total INT NOT NULL DEFAULT 8, total_findings INT NOT NULL DEFAULT 0, summary JSONB NOT NULL DEFAULT '{}'::jsonb, started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_runs_tenant ON runs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(tenant_id, status);
CREATE TABLE IF NOT EXISTS findings (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), run_id UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE, tenant_id UUID NOT NULL, tool TEXT NOT NULL, severity TEXT NOT NULL, rule_id TEXT, message TEXT, path TEXT, line_num INT, cwe TEXT, fix_signal TEXT, raw JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_findings_run      ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_run ON findings(tenant_id, run_id);
-- Additional indexes for high-traffic tenant queries
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant      ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_search     ON findings USING gin(to_tsvector('english', COALESCE(message,'') || ' ' || COALESCE(rule_id,'') || ' ' || COALESCE(path,'')));
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tenant_id, tool);
CREATE TABLE IF NOT EXISTS audit_log (seq BIGSERIAL PRIMARY KEY, tenant_id UUID NOT NULL, user_id UUID, action TEXT NOT NULL, resource TEXT, ip TEXT, payload JSONB, hash TEXT NOT NULL, prev_hash TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, seq);
CREATE TABLE IF NOT EXISTS siem_webhooks (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL REFERENCES tenants(id), label TEXT NOT NULL, type TEXT NOT NULL, url TEXT NOT NULL, secret_hash TEXT, min_sev TEXT NOT NULL DEFAULT 'HIGH', active BOOLEAN NOT NULL DEFAULT true, last_fired TIMESTAMPTZ, fire_count INT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
-- policy_rules table
CREATE TABLE IF NOT EXISTS policy_rules (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL REFERENCES tenants(id), name TEXT NOT NULL, repo_pattern TEXT NOT NULL DEFAULT '*', fail_on TEXT NOT NULL DEFAULT 'FAIL', min_score INT DEFAULT 0, max_high INT DEFAULT -1, block_secrets BOOLEAN NOT NULL DEFAULT true, block_critical BOOLEAN NOT NULL DEFAULT true, active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_policy_rules_tenant ON policy_rules(tenant_id, active);
INSERT INTO tenants (slug, name, plan) VALUES ('default', 'Default Tenant', 'enterprise') ON CONFLICT(slug) DO NOTHING;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS policy_rules, siem_webhooks, audit_log, findings, runs, api_keys, users, tenants;
-- +goose StatementEnd
