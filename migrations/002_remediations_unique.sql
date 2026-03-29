-- +goose Up
-- +goose StatementBegin
ALTER TABLE remediations ADD CONSTRAINT IF NOT EXISTS remediations_finding_id_key UNIQUE (finding_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE remediations DROP CONSTRAINT IF EXISTS remediations_finding_id_key;
-- +goose StatementEnd
