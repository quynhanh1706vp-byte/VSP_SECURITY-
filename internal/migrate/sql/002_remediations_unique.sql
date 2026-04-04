-- +goose Up
-- +goose StatementBegin
ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_id UUID;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
ALTER TABLE findings DROP COLUMN IF EXISTS remediation_id;
-- +goose StatementEnd
