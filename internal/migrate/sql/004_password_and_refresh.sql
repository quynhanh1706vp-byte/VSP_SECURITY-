-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS password_history (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, pw_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_pw_history_user ON password_history(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS refresh_tokens (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, family UUID NOT NULL DEFAULT gen_random_uuid(), rotated BOOLEAN NOT NULL DEFAULT false, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), used_at TIMESTAMPTZ);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family);
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS password_history;
-- +goose StatementEnd
