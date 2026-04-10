-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_iocs_tenant          ON iocs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_iocs_type            ON iocs(type, value);
CREATE INDEX IF NOT EXISTS idx_iocs_feed            ON iocs(feed);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_tenant ON playbook_runs(tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_pb     ON playbook_runs(playbook_id);
CREATE INDEX IF NOT EXISTS idx_log_events_ts        ON log_events(tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_log_events_sev       ON log_events(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant     ON incidents(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status     ON incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_correlation_rules_tenant ON correlation_rules(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_log_sources_tenant   ON log_sources(tenant_id);
CREATE INDEX IF NOT EXISTS idx_playbooks_tenant     ON playbooks(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_siem_webhooks_tenant ON siem_webhooks(tenant_id, active);
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_iocs_tenant;
DROP INDEX IF EXISTS idx_iocs_type;
DROP INDEX IF EXISTS idx_iocs_feed;
DROP INDEX IF EXISTS idx_playbook_runs_tenant;
DROP INDEX IF EXISTS idx_playbook_runs_pb;
DROP INDEX IF EXISTS idx_log_events_ts;
DROP INDEX IF EXISTS idx_log_events_sev;
DROP INDEX IF EXISTS idx_incidents_tenant;
DROP INDEX IF EXISTS idx_incidents_status;
DROP INDEX IF EXISTS idx_correlation_rules_tenant;
DROP INDEX IF EXISTS idx_log_sources_tenant;
DROP INDEX IF EXISTS idx_playbooks_tenant;
DROP INDEX IF EXISTS idx_siem_webhooks_tenant;
-- +goose StatementEnd
