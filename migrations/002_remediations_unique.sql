-- +goose Up
-- +goose StatementBegin
-- Fix 2026-05-10: two issues caught by CI:
--   (1) Postgres has no `ADD CONSTRAINT IF NOT EXISTS` syntax.
--   (2) The `remediations` table itself isn't created by any
--       migration — historically it was created on first startup
--       by store-layer code. On a fresh CI DB the table doesn't
--       exist when this migration runs.
-- Both fixed: skip cleanly when the table is missing, and use a
-- pg_constraint check + plain ADD CONSTRAINT once it does exist.
DO $$
BEGIN
  IF to_regclass('public.remediations') IS NULL THEN
    -- Table will be created later (by store init / a downstream
    -- migration). Nothing to do.
    RETURN;
  END IF;
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
-- Same table-existence guard as the Up section. psql --apply runs
-- the WHOLE file (it doesn't honour goose Up/Down markers), so a
-- bare `ALTER TABLE remediations` fails on a fresh DB where the
-- table hasn't been created yet by the store layer.
DO $$
BEGIN
  IF to_regclass('public.remediations') IS NOT NULL THEN
    ALTER TABLE remediations DROP CONSTRAINT IF EXISTS remediations_finding_id_key;
  END IF;
END$$;
-- +goose StatementEnd
