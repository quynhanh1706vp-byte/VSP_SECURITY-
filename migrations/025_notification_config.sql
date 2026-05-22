-- 025_notification_config.sql — per-tenant notification routing.
-- One row per tenant. Webhook URLs are stored encrypted-at-rest only at
-- the application layer (gateway encrypts before INSERT) — for the demo
-- environment they live as plaintext in this column. Production should
-- swap the column type to BYTEA + AES-GCM via internal/crypto.

CREATE TABLE IF NOT EXISTS notification_config (
    tenant_id          UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    -- Channels (empty = disabled)
    slack_webhook      TEXT NOT NULL DEFAULT '',
    teams_webhook      TEXT NOT NULL DEFAULT '',
    generic_webhook    TEXT NOT NULL DEFAULT '',
    email_recipients   TEXT NOT NULL DEFAULT '',  -- comma-separated
    pagerduty_key      TEXT NOT NULL DEFAULT '',
    -- Per-event toggles (which signals fan out to the channels above)
    alert_on_critical_finding   BOOL NOT NULL DEFAULT TRUE,
    alert_on_secret_rotated     BOOL NOT NULL DEFAULT FALSE,
    alert_on_pr_blocked         BOOL NOT NULL DEFAULT TRUE,
    alert_on_image_admission    BOOL NOT NULL DEFAULT TRUE,
    alert_on_supply_chain_fail  BOOL NOT NULL DEFAULT TRUE,
    alert_on_sso_login_failure  BOOL NOT NULL DEFAULT FALSE,
    -- Rate-limit per channel (max alerts per hour to avoid pager fatigue)
    rate_limit_per_hour         INT  NOT NULL DEFAULT 60
                                CHECK (rate_limit_per_hour BETWEEN 1 AND 10000),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lightweight outbound delivery log so the FE "Test webhook" button has
-- something to display and ops can audit alert history.
CREATE TABLE IF NOT EXISTS notification_log (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel     TEXT NOT NULL,            -- 'slack' | 'teams' | 'generic' | 'email' | 'pagerduty'
    event_type  TEXT NOT NULL,
    payload     TEXT NOT NULL DEFAULT '',
    status_code INT  NOT NULL DEFAULT 0,  -- HTTP status from the channel; 0 = not delivered
    error       TEXT NOT NULL DEFAULT '',
    sent_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS notification_log_tenant_idx
    ON notification_log(tenant_id, sent_at DESC);
