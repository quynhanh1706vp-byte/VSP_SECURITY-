-- +goose Up
-- +goose StatementBegin
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_logins INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN IF EXISTS mfa_secret;
ALTER TABLE users DROP COLUMN IF EXISTS mfa_verified;
ALTER TABLE users DROP COLUMN IF EXISTS failed_logins;
ALTER TABLE users DROP COLUMN IF EXISTS locked_until;
-- +goose StatementEnd
