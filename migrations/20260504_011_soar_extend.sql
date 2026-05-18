-- ════════════════════════════════════════════════════════════════════
-- Phase 2.1.A — SOAR engine DB layer
-- Date: 2026-05-04
--
-- Strategy: extend existing playbooks/playbook_runs tables.
-- Auto-migrate legacy `steps JSONB` array → `graph JSONB` (DAG with
-- nodes+edges) using linear chain conversion.
-- ════════════════════════════════════════════════════════════════════

BEGIN;

-- ──────────────────────────────────────────────────────────────
-- 1. EXTEND playbooks
-- ──────────────────────────────────────────────────────────────
ALTER TABLE playbooks
    ADD COLUMN IF NOT EXISTS graph          JSONB,
    ADD COLUMN IF NOT EXISTS version        INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS status         TEXT NOT NULL DEFAULT 'enabled',
    ADD COLUMN IF NOT EXISTS trigger_filter JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS secret_refs    TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS tags           TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS created_by     TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS timeout_seconds INT NOT NULL DEFAULT 300,
    ADD COLUMN IF NOT EXISTS max_retries    INT NOT NULL DEFAULT 0;

ALTER TABLE playbooks DROP CONSTRAINT IF EXISTS pb_status_chk;
ALTER TABLE playbooks ADD CONSTRAINT pb_status_chk
    CHECK (status IN ('draft','enabled','disabled','archived'));

-- Sync 'enabled' bool ↔ 'status' text trên existing rows
UPDATE playbooks SET status = CASE WHEN enabled THEN 'enabled' ELSE 'disabled' END
WHERE status IS NULL OR status = '';

-- ──────────────────────────────────────────────────────────────
-- 2. AUTO-MIGRATE legacy `steps` array → `graph` DAG format
--
-- Old format: [{"Type":"condition","Name":"X","Config":"yaml str","Desc":"..."}]
-- New format: {"nodes":[{id,type,name,config,on_failure,...}], "edges":[[from,to]]}
-- ──────────────────────────────────────────────────────────────
UPDATE playbooks
SET graph = jsonb_build_object(
    'nodes', COALESCE((
        SELECT jsonb_agg(
            jsonb_build_object(
                'id',         'n' || (idx - 1)::text,
                'type',       LOWER(COALESCE(step->>'Type', step->>'type', 'notify')),
                'name',       COALESCE(step->>'Name', step->>'name', 'Step ' || idx::text),
                'description', COALESCE(step->>'Desc', step->>'description', ''),
                'config_raw', COALESCE(step->>'Config', ''),
                'on_failure', 'abort',
                'retry',      jsonb_build_object('max', 0, 'backoff', 'fixed', 'base_ms', 1000),
                'timeout_seconds', 30
            ) ORDER BY idx
        )
        FROM jsonb_array_elements(steps) WITH ORDINALITY AS arr(step, idx)
    ), '[]'::jsonb),
    'edges', COALESCE((
        SELECT jsonb_agg(
            jsonb_build_array('n' || (idx - 1)::text, 'n' || idx::text)
        )
        FROM generate_series(1, GREATEST(jsonb_array_length(steps) - 1, 0)) AS idx
    ), '[]'::jsonb),
    'entry', 'n0',
    'metadata', jsonb_build_object('migrated_from', 'legacy_steps', 'migrated_at', NOW()::text)
)
WHERE graph IS NULL;

-- ──────────────────────────────────────────────────────────────
-- 3. EXTEND playbook_runs
-- ──────────────────────────────────────────────────────────────
ALTER TABLE playbook_runs
    ADD COLUMN IF NOT EXISTS step_results JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS error        TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS is_test      BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS triggered_by TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS duration_ms  INT,
    ADD COLUMN IF NOT EXISTS playbook_version INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS current_node TEXT NOT NULL DEFAULT '';

-- Backfill duration_ms từ duration_s
UPDATE playbook_runs SET duration_ms = duration_s * 1000
WHERE duration_ms IS NULL AND duration_s IS NOT NULL;

-- Add status values mới
ALTER TABLE playbook_runs DROP CONSTRAINT IF EXISTS pbr_status_chk;
ALTER TABLE playbook_runs ADD CONSTRAINT pbr_status_chk CHECK (
    status IN ('pending','running','success','failed','cancelled','timeout','waiting_approval','partial')
);

-- ──────────────────────────────────────────────────────────────
-- 4. NEW: playbook_versions (history for rollback)
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS playbook_versions (
    id           BIGSERIAL PRIMARY KEY,
    playbook_id  UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    version      INT NOT NULL,
    graph        JSONB NOT NULL,
    saved_by     TEXT NOT NULL DEFAULT '',
    saved_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    note         TEXT NOT NULL DEFAULT '',
    UNIQUE(playbook_id, version)
);
CREATE INDEX IF NOT EXISTS idx_pbv_pb ON playbook_versions(playbook_id, version DESC);

-- Backfill version 1 cho all existing playbooks
INSERT INTO playbook_versions(playbook_id, version, graph, saved_by, saved_at, note)
SELECT id, 1, graph, 'migration', created_at, 'Auto-created from legacy steps'
FROM playbooks
WHERE graph IS NOT NULL
ON CONFLICT (playbook_id, version) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- 5. NEW: playbook_secrets (encrypted vault)
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS playbook_secrets (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    value_encrypted BYTEA NOT NULL,
    nonce           BYTEA NOT NULL,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    last_used_by    TEXT NOT NULL DEFAULT '',
    use_count       BIGINT NOT NULL DEFAULT 0,
    UNIQUE(tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idx_pbsec_tenant ON playbook_secrets(tenant_id, name);

-- Audit access log (separate from main table để không bloat hot path)
CREATE TABLE IF NOT EXISTS playbook_secret_audit (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID NOT NULL,
    secret_name TEXT NOT NULL,
    run_id      UUID,
    action      TEXT NOT NULL,           -- 'access' | 'create' | 'update' | 'delete'
    actor       TEXT NOT NULL DEFAULT '',
    accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pbsec_audit ON playbook_secret_audit(tenant_id, accessed_at DESC);

-- ──────────────────────────────────────────────────────────────
-- 6. NEW: playbook_approvals (human-in-the-loop)
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS playbook_approvals (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id      UUID NOT NULL REFERENCES playbook_runs(id) ON DELETE CASCADE,
    node_id     TEXT NOT NULL,
    approvers   TEXT[] NOT NULL DEFAULT '{}',  -- list of email/username
    quorum      TEXT NOT NULL DEFAULT 'any',   -- any | all | m_of_n
    quorum_n    INT NOT NULL DEFAULT 1,
    status      TEXT NOT NULL DEFAULT 'pending',
    decisions   JSONB NOT NULL DEFAULT '[]'::jsonb,  -- [{by,decision,note,at}]
    note        TEXT NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at  TIMESTAMPTZ,
    CONSTRAINT pba_status_chk CHECK (status IN ('pending','approved','rejected','timeout','cancelled'))
);
CREATE INDEX IF NOT EXISTS idx_pba_run     ON playbook_approvals(run_id);
CREATE INDEX IF NOT EXISTS idx_pba_pending ON playbook_approvals(status, expires_at) WHERE status='pending';

-- ──────────────────────────────────────────────────────────────
-- 7. NEW: playbook_metrics (aggregated per playbook for dashboards)
-- ──────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW playbook_metrics AS
SELECT
    p.id           AS playbook_id,
    p.tenant_id,
    p.name,
    p.status,
    COUNT(r.id)    AS total_runs,
    COUNT(r.id) FILTER (WHERE r.status = 'success')          AS success_runs,
    COUNT(r.id) FILTER (WHERE r.status = 'failed')           AS failed_runs,
    COUNT(r.id) FILTER (WHERE r.status = 'cancelled')        AS cancelled_runs,
    COUNT(r.id) FILTER (WHERE r.status = 'timeout')          AS timeout_runs,
    COUNT(r.id) FILTER (WHERE r.status = 'waiting_approval') AS pending_approval,
    COUNT(r.id) FILTER (WHERE r.status = 'running')          AS running_now,
    AVG(r.duration_ms) FILTER (WHERE r.status = 'success')                                  AS avg_duration_ms,
    PERCENTILE_CONT(0.5)  WITHIN GROUP (ORDER BY r.duration_ms) FILTER (WHERE r.status='success') AS p50_duration_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY r.duration_ms) FILTER (WHERE r.status='success') AS p95_duration_ms,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY r.duration_ms) FILTER (WHERE r.status='success') AS p99_duration_ms,
    MAX(r.started_at)   AS last_run_at,
    ROUND(100.0 * COUNT(r.id) FILTER (WHERE r.status='success') / NULLIF(COUNT(r.id), 0), 2) AS success_rate_pct
FROM playbooks p
LEFT JOIN playbook_runs r ON r.playbook_id = p.id
GROUP BY p.id, p.tenant_id, p.name, p.status;

-- ──────────────────────────────────────────────────────────────
-- 8. NEW: playbook_triggers_dedup (anti-flood for event triggers)
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS playbook_trigger_dedup (
    fingerprint  TEXT PRIMARY KEY,        -- hash(playbook_id+trigger+context_key_fields)
    playbook_id  UUID NOT NULL,
    tenant_id    UUID NOT NULL,
    fired_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pbtd_fired ON playbook_trigger_dedup(fired_at);
-- Cleanup auto: index trên fired_at để query hết hạn

-- ──────────────────────────────────────────────────────────────
-- 9. GRANTS
-- ──────────────────────────────────────────────────────────────
GRANT ALL ON
    playbook_versions, playbook_secrets, playbook_secret_audit,
    playbook_approvals, playbook_trigger_dedup
TO vsp;

GRANT SELECT ON playbook_metrics TO vsp;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO vsp;

COMMIT;
