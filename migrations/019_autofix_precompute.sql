-- migrations/019_autofix_precompute.sql
-- H3.O — Pre-compute Worker schema additions
-- Idempotent: safe to run multiple times.

CREATE TABLE IF NOT EXISTS autofix_precompute_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID NOT NULL,
    tenant_id       UUID NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    total           INTEGER NOT NULL DEFAULT 0,
    completed       INTEGER NOT NULL DEFAULT 0,
    failed          INTEGER NOT NULL DEFAULT 0,
    skipped         INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms  INTEGER,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One job per run (re-run on conflict updates)
CREATE UNIQUE INDEX IF NOT EXISTS idx_precompute_jobs_run
  ON autofix_precompute_jobs(run_id);

-- Status filter for UI
CREATE INDEX IF NOT EXISTS idx_precompute_jobs_status
  ON autofix_precompute_jobs(status, created_at DESC);

-- Tenant scoping
CREATE INDEX IF NOT EXISTS idx_precompute_jobs_tenant
  ON autofix_precompute_jobs(tenant_id, created_at DESC);

-- Helper: which runs need pre-compute (for worker scan query)
CREATE INDEX IF NOT EXISTS idx_runs_finished
  ON runs(status, finished_at DESC)
  WHERE finished_at IS NOT NULL;

-- Confirm cache schema is compatible (no changes — just verification)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='autofix_cache') THEN
    RAISE EXCEPTION 'autofix_cache table missing — run H3.N migration first';
  END IF;
END$$;

-- Done
SELECT 'H3.O migration applied successfully' AS status;
