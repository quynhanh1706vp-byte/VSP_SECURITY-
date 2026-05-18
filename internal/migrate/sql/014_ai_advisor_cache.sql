-- +goose Up
-- +goose StatementBegin

-- AI Advisor response cache — avoid duplicate LLM calls for identical findings.
-- Phase 4.5.2 · April 2026
CREATE TABLE IF NOT EXISTS ai_advisor_cache (
    id              BIGSERIAL PRIMARY KEY,
    cache_key       TEXT NOT NULL UNIQUE,
    framework       TEXT NOT NULL,
    control_id      TEXT NOT NULL,
    finding_summary TEXT NOT NULL,
    response_json   JSONB NOT NULL,
    mode            TEXT NOT NULL DEFAULT 'claude',  -- claude / local
    model           TEXT,
    tokens_in       INT,
    tokens_out      INT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    use_count       INT NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_aiadvisor_cache_key       ON ai_advisor_cache(cache_key);
CREATE INDEX IF NOT EXISTS idx_aiadvisor_cache_framework ON ai_advisor_cache(framework, control_id);
CREATE INDEX IF NOT EXISTS idx_aiadvisor_cache_used      ON ai_advisor_cache(last_used_at DESC);

-- Feedback table — users mark suggestions helpful/not
CREATE TABLE IF NOT EXISTS ai_advisor_feedback (
    id              BIGSERIAL PRIMARY KEY,
    cache_id        BIGINT NOT NULL REFERENCES ai_advisor_cache(id) ON DELETE CASCADE,
    tenant_id       TEXT NOT NULL,
    user_email      TEXT,
    rating          TEXT NOT NULL CHECK (rating IN ('helpful','not_helpful','partially')),
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_aiadvisor_fb_cache ON ai_advisor_feedback(cache_id);

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ai_advisor_feedback;
DROP TABLE IF EXISTS ai_advisor_cache;
-- +goose StatementEnd
