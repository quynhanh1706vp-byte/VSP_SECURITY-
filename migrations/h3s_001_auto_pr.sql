-- =====================================================================
-- H3.S Auto-PR Creation — Migration 001
-- File: migrations/h3s_001_auto_pr.sql
-- Run: psql -h localhost -U vsp -d vsp_go -f h3s_001_auto_pr.sql
-- =====================================================================

BEGIN;

-- ── Repo configuration (multi-tenant, per-tenant repos) ─────────────────
CREATE TABLE IF NOT EXISTS repo_config (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID,                       -- NULL = global default
    nickname        TEXT         NOT NULL,      -- "main-repo", "infra", etc.
    platform        TEXT         NOT NULL,      -- 'github_enterprise' | 'github' | 'gitlab' | 'gitea'
    base_url        TEXT         NOT NULL,      -- 'https://ghe.company.com' (for self-host)
    api_url         TEXT,                        -- 'https://ghe.company.com/api/v3'
    repo_owner      TEXT         NOT NULL,
    repo_name       TEXT         NOT NULL,
    default_branch  TEXT         NOT NULL DEFAULT 'main',
    token_encrypted BYTEA        NOT NULL,      -- AES-256-GCM (key from VSP_REPO_KEY env)
    token_user      TEXT,                        -- bot user (e.g. "vsp-autofix-bot")
    webhook_secret  TEXT,                        -- HMAC-SHA256 secret for webhook verify
    
    -- SLA scheduler config
    auto_pr_enabled BOOLEAN      NOT NULL DEFAULT false,
    sla_severity    TEXT[]       DEFAULT ARRAY['critical','high'],
    sla_min_score   SMALLINT     DEFAULT 80,    -- only auto-PR if H3.Q score ≥ this
    sla_max_per_day INT          DEFAULT 10,    -- rate limit
    
    enabled         BOOLEAN      NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT repo_config_platform_chk
        CHECK (platform IN ('github_enterprise','github','gitlab','gitea')),
    CONSTRAINT repo_config_owner_name_uq
        UNIQUE (tenant_id, repo_owner, repo_name)
);

CREATE INDEX IF NOT EXISTS idx_repo_config_tenant
    ON repo_config (tenant_id) WHERE enabled = true;

-- ── PR records (one per fix submitted) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS autofix_pr (
    id              BIGSERIAL    PRIMARY KEY,
    tenant_id       UUID,                          -- denormalized from repo_config for fast filter
    repo_config_id  UUID         NOT NULL REFERENCES repo_config(id) ON DELETE CASCADE,
    
    -- Source data (denormalized for audit even if cache expires)
    cache_key       TEXT         NOT NULL,
    finding_id      TEXT         NOT NULL,
    rule_id         TEXT,
    severity        TEXT,
    file_path       TEXT,
    
    -- PR metadata
    branch_name     TEXT         NOT NULL,
    pr_number       INT,                           -- NULL until provider returns it
    pr_url          TEXT,
    pr_title        TEXT,
    
    -- Lifecycle
    pr_status       TEXT         NOT NULL DEFAULT 'pending',
        -- pending → creating → created → merged | closed | conflict | failed
    error_msg       TEXT,
    
    -- Origin
    created_by      TEXT         NOT NULL,         -- user uid OR 'sla_scheduler'
    trigger_type    TEXT         NOT NULL,         -- 'manual' | 'sla'
    validation_score SMALLINT,                     -- snapshot from H3.Q at PR time
    
    -- Timestamps
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    pushed_at       TIMESTAMPTZ,
    merged_at       TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    
    CONSTRAINT autofix_pr_status_chk
        CHECK (pr_status IN ('pending','creating','created','merged','closed','conflict','failed')),
    CONSTRAINT autofix_pr_trigger_chk
        CHECK (trigger_type IN ('manual','sla')),
    -- One PR per (cache_key + repo) — re-creating after close requires explicit override
    CONSTRAINT autofix_pr_dedup_uq
        UNIQUE (cache_key, repo_config_id)
);

CREATE INDEX IF NOT EXISTS idx_autofix_pr_status
    ON autofix_pr (pr_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_autofix_pr_tenant
    ON autofix_pr (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_autofix_pr_finding
    ON autofix_pr (finding_id);

-- ── Webhook event log (CMMC AU-2 audit) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS autofix_pr_webhook (
    id              BIGSERIAL    PRIMARY KEY,
    repo_config_id  UUID         REFERENCES repo_config(id) ON DELETE SET NULL,
    pr_id           BIGINT       REFERENCES autofix_pr(id) ON DELETE SET NULL,
    event_type      TEXT         NOT NULL,        -- 'pull_request.opened', 'merged', etc.
    event_action    TEXT,
    delivery_id     TEXT,                          -- X-GitHub-Delivery header
    signature_valid BOOLEAN,
    payload_hash    TEXT,                          -- sha256 of payload (no PII)
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_autofix_pr_webhook_pr
    ON autofix_pr_webhook (pr_id, created_at DESC);

-- ── Stats view ──────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_autofix_pr_stats AS
SELECT
    pr_status,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE trigger_type = 'manual') AS manual_count,
    COUNT(*) FILTER (WHERE trigger_type = 'sla')    AS sla_count,
    ROUND(AVG(validation_score)::numeric, 1)         AS avg_score,
    MAX(created_at)                                   AS last_pr
FROM autofix_pr
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY pr_status;

-- Remediation rate fix — link to findings table for "Remediation rate=0%" bug
CREATE OR REPLACE VIEW v_remediation_progress AS
SELECT
    DATE_TRUNC('day', merged_at) AS day,
    COUNT(*) AS prs_merged,
    COUNT(DISTINCT finding_id) AS findings_remediated
FROM autofix_pr
WHERE pr_status = 'merged' AND merged_at IS NOT NULL
GROUP BY DATE_TRUNC('day', merged_at)
ORDER BY day DESC;

COMMIT;

-- Verify
\echo ''
\echo '── Tables ──'
\dt repo_config autofix_pr autofix_pr_webhook
\echo ''
\echo '── repo_config schema ──'
\d repo_config
\echo ''
\echo '── autofix_pr schema ──'
\d autofix_pr
\echo ''
\echo '── Stats views ──'
SELECT * FROM v_autofix_pr_stats;
SELECT * FROM v_remediation_progress LIMIT 5;
