-- =====================================================================
-- H3.T Agentic Autofix + H3.W Telemetry — Migration
-- File: migrations/h3tw_001_agentic_telemetry.sql
-- =====================================================================

BEGIN;

-- ── H3.T: Agentic reasoning traces ──────────────────────────────────
CREATE TABLE IF NOT EXISTS agentic_trace (
    id              BIGSERIAL PRIMARY KEY,
    cache_key       TEXT        NOT NULL,
    finding_id      TEXT        NOT NULL,
    session_id      UUID        NOT NULL DEFAULT gen_random_uuid(),
    turn_number     SMALLINT    NOT NULL,        -- 0..max_turns
    role            TEXT        NOT NULL,        -- 'system'|'llm'|'tool'|'final'
    tool_name       TEXT,                         -- 'read_file'|'grep'|'ast_parse'|'check_imports'|null
    tool_input      JSONB,
    tool_output     JSONB,                        -- truncated to 4KB
    llm_thought     TEXT,                         -- reasoning text (NOT full prompt — privacy)
    tokens_used     INT         NOT NULL DEFAULT 0,
    duration_ms     INT         NOT NULL DEFAULT 0,
    converged       BOOLEAN     NOT NULL DEFAULT FALSE,
    error_msg       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT agentic_trace_role_chk
        CHECK (role IN ('system','llm','tool','final')),
    CONSTRAINT agentic_trace_turn_chk
        CHECK (turn_number >= 0 AND turn_number <= 10)
);

CREATE INDEX IF NOT EXISTS idx_agentic_trace_session
    ON agentic_trace (session_id, turn_number);
CREATE INDEX IF NOT EXISTS idx_agentic_trace_finding
    ON agentic_trace (finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agentic_trace_cache
    ON agentic_trace (cache_key);

-- ── H3.W: Telemetry counters (Prometheus-compatible) ────────────────
CREATE TABLE IF NOT EXISTS telemetry_counter (
    id              BIGSERIAL PRIMARY KEY,
    metric_name     TEXT        NOT NULL,
    label_pairs     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    value           DOUBLE PRECISION NOT NULL DEFAULT 0,
    bucket_minute   TIMESTAMPTZ NOT NULL,         -- bucketed to minute
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_telemetry_counter_name_bucket
    ON telemetry_counter (metric_name, bucket_minute DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_counter_recent
    ON telemetry_counter (bucket_minute DESC)
    ;

-- ── H3.W: Histogram observations ────────────────────────────────────
CREATE TABLE IF NOT EXISTS telemetry_histogram (
    id              BIGSERIAL PRIMARY KEY,
    metric_name     TEXT        NOT NULL,
    label_pairs     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    value_seconds   DOUBLE PRECISION NOT NULL,
    bucket_minute   TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_telemetry_histogram_name_bucket
    ON telemetry_histogram (metric_name, bucket_minute DESC);

-- ── H3.W: Span/trace storage (lightweight; for OTLP fallback) ────────
CREATE TABLE IF NOT EXISTS telemetry_span (
    id              BIGSERIAL PRIMARY KEY,
    trace_id        TEXT        NOT NULL,
    span_id         TEXT        NOT NULL,
    parent_span_id  TEXT,
    operation_name  TEXT        NOT NULL,
    start_time      TIMESTAMPTZ NOT NULL,
    end_time        TIMESTAMPTZ,
    duration_ms     INT,
    status_code     SMALLINT,                     -- 0=OK, 1=Error
    attributes      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    events          JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_telemetry_span_trace ON telemetry_span (trace_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_span_op    ON telemetry_span (operation_name, start_time DESC);

-- ── Stats views ─────────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_agentic_stats AS
SELECT
    DATE_TRUNC('hour', created_at) AS hour,
    COUNT(DISTINCT session_id)     AS sessions,
    SUM(tokens_used)               AS total_tokens,
    AVG(turn_number) FILTER (WHERE role = 'final') AS avg_turns,
    COUNT(*) FILTER (WHERE role = 'final' AND converged = TRUE)::float /
        NULLIF(COUNT(DISTINCT session_id), 0) AS convergence_rate,
    AVG(duration_ms)               AS avg_duration_ms
FROM agentic_trace
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY DATE_TRUNC('hour', created_at)
ORDER BY hour DESC;

CREATE OR REPLACE VIEW v_telemetry_recent AS
SELECT
    metric_name,
    label_pairs,
    SUM(value)                     AS sum_value,
    COUNT(*)                       AS sample_count,
    MAX(bucket_minute)             AS latest
FROM telemetry_counter
WHERE bucket_minute > NOW() - INTERVAL '1 hour'
GROUP BY metric_name, label_pairs;

COMMIT;

\echo ''
\echo '── Tables created ──'
\dt agentic_trace telemetry_counter telemetry_histogram telemetry_span
\echo ''
\echo '── Views ──'
\dv v_agentic_stats v_telemetry_recent
