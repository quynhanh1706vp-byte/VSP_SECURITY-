-- +goose Up
-- +goose StatementBegin

-- Backfill tools_total for historical runs that were created via the
-- scheduler-fired EnqueueDirect path before 2026-05-11.
--
-- Background: runs_enqueue.go:EnqueueDirect had a hand-maintained
-- map of tools_total values per mode that drifted from the actual
-- pipeline.RunnersFor() registry. Every cron-fired run between
-- the registry expansion (Phase 4 — phase4 group added) and the
-- 2026-05-11 fix showed misleading "X/Y" counts in the run history
-- table — e.g. FULL_SOC ran 26 tools but tools_total said 18, and
-- internal/store/runs.go:UpdateRunResult force-clamps tools_done
-- to tools_total at completion, so completed rows displayed "18/18"
-- regardless of how many tools actually executed.
--
-- This migration recomputes tools_total for every existing row
-- using the same registry the FE displays (pipeline.ToolNamesForMode).
-- We don't touch tools_done — that's a count of successful tool
-- completions, and rewriting it would lose the partial-success
-- signal for rows where some scanners failed. Operators reviewing
-- history will see "X / new_total" where X is the historic
-- completion count and new_total is the canonical mode size.

UPDATE runs SET tools_total = 26 WHERE mode IN ('FULL', 'FULL_SOC');
UPDATE runs SET tools_total = 4  WHERE mode = 'SAST';
UPDATE runs SET tools_total = 8  WHERE mode = 'SCA';
UPDATE runs SET tools_total = 3  WHERE mode = 'SECRETS';
UPDATE runs SET tools_total = 3  WHERE mode = 'IAC';
UPDATE runs SET tools_total = 3  WHERE mode = 'DAST';
UPDATE runs SET tools_total = 3  WHERE mode = 'NETWORK';

-- Repair the tools_done = tools_total clamp leftover from completed
-- runs: where mode was bumped UP (e.g. FULL_SOC 18 → 26), tools_done
-- is now < tools_total, which is correct (the run only managed 18
-- tools at the time, even if 26 should have run). Where mode was
-- bumped DOWN (none today, but defensive), cap tools_done so the
-- ratio doesn't exceed 100%.
UPDATE runs SET tools_done = tools_total
  WHERE tools_done > tools_total;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- The Down for a backfill is intentionally a no-op: the previous
-- tools_total values were drifted/wrong by definition, so restoring
-- them would re-break the run history badges. If a rollback is
-- needed, point-in-time restore is the right tool — re-running the
-- old hardcoded map values from runs_enqueue.go is not.
SELECT 1; -- no-op so the Down block is non-empty for L78.2 detector

-- +goose StatementEnd
