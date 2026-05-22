-- Rollback Phase 2.1.A migration
-- WARNING: drops 4 new tables + 1 view, removes columns added to playbooks/playbook_runs.
-- Original `steps` data preserved (migration only ADDED `graph`, didn't DROP).

BEGIN;

DROP VIEW  IF EXISTS playbook_metrics;
DROP TABLE IF EXISTS playbook_trigger_dedup CASCADE;
DROP TABLE IF EXISTS playbook_approvals CASCADE;
DROP TABLE IF EXISTS playbook_secret_audit CASCADE;
DROP TABLE IF EXISTS playbook_secrets CASCADE;
DROP TABLE IF EXISTS playbook_versions CASCADE;

ALTER TABLE playbooks DROP CONSTRAINT IF EXISTS pb_status_chk;
ALTER TABLE playbooks
    DROP COLUMN IF EXISTS graph,
    DROP COLUMN IF EXISTS version,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS trigger_filter,
    DROP COLUMN IF EXISTS secret_refs,
    DROP COLUMN IF EXISTS tags,
    DROP COLUMN IF EXISTS created_by,
    DROP COLUMN IF EXISTS timeout_seconds,
    DROP COLUMN IF EXISTS max_retries;

ALTER TABLE playbook_runs DROP CONSTRAINT IF EXISTS pbr_status_chk;
ALTER TABLE playbook_runs
    DROP COLUMN IF EXISTS step_results,
    DROP COLUMN IF EXISTS error,
    DROP COLUMN IF EXISTS is_test,
    DROP COLUMN IF EXISTS triggered_by,
    DROP COLUMN IF EXISTS duration_ms,
    DROP COLUMN IF EXISTS playbook_version,
    DROP COLUMN IF EXISTS current_node;

COMMIT;
