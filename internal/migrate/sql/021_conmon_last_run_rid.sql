-- +goose Up
-- +goose StatementBegin

-- conmon_schedules.last_run_id was declared BIGINT (migration 013),
-- but runs.id is UUID and runs.rid is TEXT. The conmon scheduler
-- engine therefore stored 0 in last_run_id forever (see explicit
-- comment in cmd/gateway/main.go:1148-1150), the DetectDrift call
-- never fired, and conmon_schedules.last_verdict stayed NULL — the
-- user-visible "—" in the ConMon Active Schedules table's LAST
-- VERDICT column.
--
-- Add a TEXT column that the conmon scheduler can actually populate
-- with the RID string returned by runsH.EnqueueDirect. Worker
-- post-scan hook then matches conmon_schedules.last_run_rid =
-- payload.RID and writes the gate verdict (PASS/FAIL/WARN) into
-- last_verdict, so the UI fills in within seconds of the run
-- completing.
--
-- The legacy BIGINT last_run_id column stays for backwards-compat
-- with anything that reads it; new code reads last_run_rid.

ALTER TABLE conmon_schedules
    ADD COLUMN IF NOT EXISTS last_run_rid TEXT;

CREATE INDEX IF NOT EXISTS idx_conmon_schedules_last_run_rid
    ON conmon_schedules(last_run_rid)
    WHERE last_run_rid IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_conmon_schedules_last_run_rid;
ALTER TABLE conmon_schedules DROP COLUMN IF EXISTS last_run_rid;

-- +goose StatementEnd
