CREATE TABLE IF NOT EXISTS schedules (
    id            VARCHAR(40) PRIMARY KEY,
    name          VARCHAR(200) NOT NULL,
    mode          VARCHAR(20)  NOT NULL,      -- SAST | SCA | SECRETS | IAC | DAST | NETWORK | FULL | FULL_SOC
    profile       VARCHAR(40)  NOT NULL,
    cron          VARCHAR(40)  NOT NULL,      -- 5-field cron
    src           TEXT,                       -- repo path / target URL
    tags          TEXT[],
    enabled       BOOLEAN DEFAULT TRUE,
    next_run_at   TIMESTAMPTZ,
    last_run_at   TIMESTAMPTZ,
    last_status   VARCHAR(20),
    last_gate     VARCHAR(8),
    last_run_id   VARCHAR(40),
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    created_by    VARCHAR(255),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sched_next     ON schedules(next_run_at) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_sched_enabled  ON schedules(enabled);

-- Audit
CREATE TABLE IF NOT EXISTS schedule_runs (
    id            BIGSERIAL PRIMARY KEY,
    schedule_id   VARCHAR(40) REFERENCES schedules(id) ON DELETE CASCADE,
    run_id        VARCHAR(40),
    triggered_at  TIMESTAMPTZ DEFAULT NOW(),
    triggered_by  VARCHAR(255),               -- 'cron' | user email if manual
    status        VARCHAR(20),
    duration_ms   INT,
    findings      INT,
    gate          VARCHAR(8)
);

CREATE INDEX IF NOT EXISTS idx_schedrun_sched ON schedule_runs(schedule_id, triggered_at DESC);

-- Trigger: update updated_at
CREATE OR REPLACE FUNCTION schedules_updated_at_trigger() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS schedules_updated_at ON schedules;
CREATE TRIGGER schedules_updated_at BEFORE UPDATE ON schedules
    FOR EACH ROW EXECUTE FUNCTION schedules_updated_at_trigger();
