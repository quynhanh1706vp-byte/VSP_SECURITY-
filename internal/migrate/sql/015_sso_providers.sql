-- +goose Up
-- +goose StatementBegin

-- SSO provider configurations per tenant
-- Phase 4.5.3 · April 2026
CREATE TABLE IF NOT EXISTS sso_providers (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL,             -- display name
    type            TEXT NOT NULL CHECK (type IN ('oidc','saml')),
    issuer_url      TEXT NOT NULL,             -- OIDC issuer / SAML entity ID
    client_id       TEXT NOT NULL,
    client_secret   TEXT NOT NULL,             -- encrypted; gateway decrypts at use
    redirect_uri    TEXT NOT NULL,             -- our callback URL
    scopes          TEXT NOT NULL DEFAULT 'openid email profile',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    -- Discovery cache to avoid hitting /.well-known/openid-configuration on every login
    discovery_json  JSONB,
    discovery_at    TIMESTAMPTZ,
    -- Optional: restrict access to email domain, group membership, etc.
    allowed_domains TEXT[],
    default_role    TEXT NOT NULL DEFAULT 'analyst',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sso_providers_tenant_name ON sso_providers(tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_sso_providers_enabled ON sso_providers(enabled) WHERE enabled = true;

-- Pending login state (state + nonce + PKCE verifier)
-- Short-lived; cleaned up periodically.
CREATE TABLE IF NOT EXISTS sso_login_states (
    state           TEXT PRIMARY KEY,
    provider_id     BIGINT NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    nonce           TEXT NOT NULL,
    pkce_verifier   TEXT NOT NULL,
    redirect_after  TEXT,                       -- where to send user after login
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '10 minutes')
);

CREATE INDEX IF NOT EXISTS idx_sso_states_expires ON sso_login_states(expires_at);

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS sso_login_states;
DROP TABLE IF EXISTS sso_providers;
-- +goose StatementEnd
