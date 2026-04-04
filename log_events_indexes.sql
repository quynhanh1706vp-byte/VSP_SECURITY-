-- migrations/XXXXXX_log_events_correlation_index.sql
-- Thêm indexes cho log_events để correlation engine query nhanh trong time window

CREATE TABLE IF NOT EXISTS log_events (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID        NOT NULL,
    ts         TIMESTAMPTZ NOT NULL,
    host       TEXT,
    process    TEXT,
    severity   TEXT,
    facility   TEXT,
    message    TEXT,
    source_ip  TEXT,
    format     TEXT,
    raw        TEXT,
    fields     JSONB       DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index chính cho correlation engine: tenant + time window
CREATE INDEX IF NOT EXISTS idx_log_events_tenant_ts
    ON log_events(tenant_id, ts DESC);

-- Index severity để filter nhanh
CREATE INDEX IF NOT EXISTS idx_log_events_severity
    ON log_events(tenant_id, severity, ts DESC);

-- Index process/facility để match sources
CREATE INDEX IF NOT EXISTS idx_log_events_process
    ON log_events(tenant_id, LOWER(process), ts DESC);

CREATE INDEX IF NOT EXISTS idx_log_events_facility
    ON log_events(tenant_id, LOWER(facility), ts DESC);

-- GIN index cho full-text search trên message (cho condition message~keyword)
CREATE INDEX IF NOT EXISTS idx_log_events_message_gin
    ON log_events USING gin(to_tsvector('english', COALESCE(message, '')));

-- Auto-partition cleanup: xóa events cũ hơn 90 ngày (chạy bởi retention worker)
-- Retention worker trong siem/retention.go đã handle việc này
