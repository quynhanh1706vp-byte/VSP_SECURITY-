-- H3.N: AI-Powered Autofix cache
-- Stores LLM-generated fix suggestions, keyed by content-hash of the finding.
-- TTL 30 days by default — re-generated after expiry to pick up model improvements.

CREATE TABLE IF NOT EXISTS autofix_cache (
    id              BIGSERIAL PRIMARY KEY,
    cache_key       TEXT UNIQUE NOT NULL,
    finding_id      TEXT,
    provider        TEXT NOT NULL,
    model           TEXT NOT NULL,
    suggested_code  TEXT NOT NULL,
    rationale       TEXT,
    confidence      TEXT CHECK (confidence IN ('high','medium','low')),
    breaking_change BOOLEAN DEFAULT FALSE,
    tokens_used     INT,
    latency_ms      INT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    expires_at      TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days'
);

CREATE INDEX IF NOT EXISTS idx_autofix_cache_key ON autofix_cache(cache_key);
CREATE INDEX IF NOT EXISTS idx_autofix_cache_finding ON autofix_cache(finding_id);
CREATE INDEX IF NOT EXISTS idx_autofix_cache_expires ON autofix_cache(expires_at);

COMMENT ON TABLE autofix_cache IS 'H3.N: LLM-generated fix cache. CMMC AU-2 — stores suggestion content but NOT prompt/response audit metadata (those go to audit_log).';
