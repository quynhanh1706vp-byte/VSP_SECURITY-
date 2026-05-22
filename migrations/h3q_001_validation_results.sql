-- =====================================================================
-- H3.Q Fix Validation Pipeline — Migration 001
-- File: migrations/h3q_001_validation_results.sql
-- Run: psql -h localhost -U vsp -d vsp_go -f h3q_001_migration.sql
-- =====================================================================

BEGIN;

-- Validation results — one row per (cache_key, validator_name)
CREATE TABLE IF NOT EXISTS autofix_validation (
    id              BIGSERIAL PRIMARY KEY,
    cache_key       TEXT        NOT NULL,
    finding_id      UUID        NOT NULL,
    validator       TEXT        NOT NULL,         -- 'syntax' | 'idempotent' | 'ast_diff' | 'compile' | 'lint'
    status          TEXT        NOT NULL,         -- 'pass' | 'fail' | 'skip' | 'error'
    confidence_in   TEXT,                          -- confidence reported by LLM ('high'|'medium'|'low')
    confidence_out  TEXT,                          -- confidence after validation gate (downgraded if fail)
    duration_ms     INT         NOT NULL DEFAULT 0,
    error_msg       TEXT,                          -- truncated error from validator (no source code stored — CMMC AU-2)
    metadata        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT autofix_validation_status_chk
        CHECK (status IN ('pass','fail','skip','error')),
    CONSTRAINT autofix_validation_validator_chk
        CHECK (validator IN ('syntax','idempotent','ast_diff','compile','lint','line_scope'))
);

CREATE INDEX IF NOT EXISTS idx_autofix_validation_cache_key
    ON autofix_validation (cache_key);
CREATE INDEX IF NOT EXISTS idx_autofix_validation_finding
    ON autofix_validation (finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_autofix_validation_status
    ON autofix_validation (status, validator)
    WHERE status IN ('fail','error');

-- Add validation summary column to autofix_cache (denormalized for fast UI)
ALTER TABLE autofix_cache
    ADD COLUMN IF NOT EXISTS validation_score   SMALLINT,         -- 0-100, NULL = not validated
    ADD COLUMN IF NOT EXISTS validation_status  TEXT,             -- 'pass' | 'fail' | 'partial' | NULL
    ADD COLUMN IF NOT EXISTS validation_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS confidence_final   TEXT;             -- after validation gate

CREATE INDEX IF NOT EXISTS idx_autofix_cache_val_status
    ON autofix_cache (validation_status)
    WHERE validation_status IS NOT NULL;

-- Aggregate stats view (used by /api/v1/autofix/validation/stats)
CREATE OR REPLACE VIEW v_autofix_validation_stats AS
SELECT
    validator,
    COUNT(*)                                                   AS total,
    COUNT(*) FILTER (WHERE status = 'pass')                    AS pass_count,
    COUNT(*) FILTER (WHERE status = 'fail')                    AS fail_count,
    COUNT(*) FILTER (WHERE status = 'skip')                    AS skip_count,
    COUNT(*) FILTER (WHERE status = 'error')                   AS error_count,
    ROUND(100.0 * COUNT(*) FILTER (WHERE status='pass') /
          NULLIF(COUNT(*) FILTER (WHERE status IN ('pass','fail')), 0), 1) AS pass_rate_pct,
    ROUND(AVG(duration_ms)::numeric, 1)                        AS avg_duration_ms,
    MAX(created_at)                                             AS last_run
FROM autofix_validation
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY validator
ORDER BY validator;

COMMIT;

-- Verify
\echo ''
\echo '── Tables ──'
\d autofix_validation
\echo ''
\echo '── Cache schema ──'
\d autofix_cache
\echo ''
\echo '── Stats view (empty until first validation) ──'
SELECT * FROM v_autofix_validation_stats;
