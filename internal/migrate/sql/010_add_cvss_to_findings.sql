-- +goose Up
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss FLOAT DEFAULT 0;

-- +goose Down
ALTER TABLE findings DROP COLUMN IF EXISTS cvss;
