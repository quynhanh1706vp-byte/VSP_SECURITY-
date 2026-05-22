-- 027_threat_hunt.sql — saved + scheduled threat-hunt queries.
-- The free-tier panel already has live ad-hoc search via /api/v1/logs/hunt.
-- This migration adds PRO-grade persistence so analysts can save queries,
-- schedule them on a cadence (matches Configure → default_lookback_hours
-- and query_timeout_seconds set per-tenant in feature_config) and review
-- a result history.

CREATE TABLE IF NOT EXISTS hunt_queries (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name              TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description       TEXT NOT NULL DEFAULT '',
    -- Lucene-style search expression evaluated by /api/v1/logs/hunt
    -- (e.g. `event_type:auth status:fail src_ip:10.* user.role:admin`).
    query             TEXT NOT NULL CHECK (length(query) BETWEEN 1 AND 4000),
    -- Lookback window per run, hours. NULL = use tenant Configure default.
    lookback_hours    INT  CHECK (lookback_hours IS NULL OR (lookback_hours BETWEEN 1 AND 720)),
    -- Optional cron schedule. NULL = manual-run only.
    schedule_cron     TEXT,
    -- Comma-separated MITRE ATT&CK technique IDs e.g. "T1078,T1190"
    mitre_techniques  TEXT NOT NULL DEFAULT '',
    -- Minimum severity below which results aren't surfaced as incidents.
    min_match_severity TEXT NOT NULL DEFAULT 'medium'
                       CHECK (min_match_severity IN ('critical','high','medium','low')),
    enabled           BOOL NOT NULL DEFAULT TRUE,
    created_by        TEXT NOT NULL DEFAULT '',
    last_run_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);
CREATE INDEX IF NOT EXISTS hunt_queries_tenant_idx
    ON hunt_queries(tenant_id, enabled, last_run_at DESC);

CREATE TABLE IF NOT EXISTS hunt_results (
    id            BIGSERIAL PRIMARY KEY,
    query_id      UUID NOT NULL REFERENCES hunt_queries(id) ON DELETE CASCADE,
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ran_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_ms   INT  NOT NULL DEFAULT 0,
    match_count   INT  NOT NULL DEFAULT 0,
    samples       JSONB NOT NULL DEFAULT '[]'::jsonb,  -- top N matched events for review
    error         TEXT NOT NULL DEFAULT '',
    triggered_by  TEXT NOT NULL DEFAULT 'manual'        -- 'manual' | 'schedule'
);
CREATE INDEX IF NOT EXISTS hunt_results_query_idx
    ON hunt_results(query_id, ran_at DESC);
CREATE INDEX IF NOT EXISTS hunt_results_tenant_idx
    ON hunt_results(tenant_id, ran_at DESC);
