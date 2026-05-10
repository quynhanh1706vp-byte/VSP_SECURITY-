-- +goose Up
-- +goose StatementBegin
-- Fix 2026-05-10: Postgres has no `ADD CONSTRAINT IF NOT EXISTS`
-- syntax. Wrap in a DO block that checks pg_constraint for the
-- target name first. Caught by CI when the workflow re-applied
-- migrations on a fresh DB.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'remediations_finding_id_key'
       AND conrelid = 'remediations'::regclass
  ) THEN
    ALTER TABLE remediations
      ADD CONSTRAINT remediations_finding_id_key UNIQUE (finding_id);
  END IF;
END$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE remediations DROP CONSTRAINT IF EXISTS remediations_finding_id_key;
-- +goose StatementEnd
