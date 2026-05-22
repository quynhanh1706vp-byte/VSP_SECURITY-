-- +goose Up
-- +goose StatementBegin
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS run_id uuid;
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS resolved_by text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_rem_run ON remediations(run_id);
COMMENT ON COLUMN remediations.run_id IS 'FK to scan/playbook run that created this remediation; nullable for manual entries';
COMMENT ON COLUMN remediations.resolved_by IS 'Actor that resolved the remediation (user UUID, "auto-h3u-worker", etc.)';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_rem_run;
ALTER TABLE remediations DROP COLUMN IF EXISTS resolved_by;
ALTER TABLE remediations DROP COLUMN IF EXISTS run_id;
-- +goose StatementEnd
