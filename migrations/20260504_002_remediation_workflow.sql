-- Add workflow columns to remediation_items
ALTER TABLE remediation_items
    ADD COLUMN IF NOT EXISTS status          VARCHAR(20)  NOT NULL DEFAULT 'open',
    ADD COLUMN IF NOT EXISTS assignee        VARCHAR(255),
    ADD COLUMN IF NOT EXISTS priority        VARCHAR(4)   DEFAULT 'P3',
    ADD COLUMN IF NOT EXISTS resolved_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS resolved_by     VARCHAR(255),
    ADD COLUMN IF NOT EXISTS resolution_note TEXT,
    ADD COLUMN IF NOT EXISTS sla_due         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS reopened_count  INT DEFAULT 0;

-- Allowed statuses constraint (dùng CHECK, không CREATE TYPE để dễ rollback)
ALTER TABLE remediation_items DROP CONSTRAINT IF EXISTS rem_status_check;
ALTER TABLE remediation_items ADD CONSTRAINT rem_status_check CHECK (
    status IN ('open','in_progress','resolved','accepted_risk','false_positive','suppressed')
);

ALTER TABLE remediation_items DROP CONSTRAINT IF EXISTS rem_priority_check;
ALTER TABLE remediation_items ADD CONSTRAINT rem_priority_check CHECK (
    priority IN ('P1','P2','P3','P4')
);

CREATE INDEX IF NOT EXISTS idx_rem_status   ON remediation_items(status);
CREATE INDEX IF NOT EXISTS idx_rem_assignee ON remediation_items(assignee) WHERE status NOT IN ('resolved','false_positive');
CREATE INDEX IF NOT EXISTS idx_rem_sla      ON remediation_items(sla_due) WHERE status IN ('open','in_progress');

-- History / audit trail
CREATE TABLE IF NOT EXISTS remediation_history (
    id          BIGSERIAL PRIMARY KEY,
    item_id     VARCHAR(64) NOT NULL,
    actor       VARCHAR(255) NOT NULL,
    action      VARCHAR(40) NOT NULL,        -- assign | status_change | comment | sla_extend | reopen
    from_value  TEXT,
    to_value    TEXT,
    note        TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (item_id) REFERENCES remediation_items(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_remhist_item ON remediation_history(item_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_remhist_actor ON remediation_history(actor, created_at DESC);

-- View: KPI counts (để frontend gọi 1 query)
CREATE OR REPLACE VIEW remediation_kpis AS
SELECT
    COUNT(*) FILTER (WHERE status = 'open')           AS open_count,
    COUNT(*) FILTER (WHERE status = 'in_progress')    AS in_progress_count,
    COUNT(*) FILTER (WHERE status = 'resolved')       AS resolved_count,
    COUNT(*) FILTER (WHERE status = 'accepted_risk')  AS accepted_count,
    COUNT(*) FILTER (WHERE status = 'false_positive') AS fp_count,
    COUNT(*) FILTER (WHERE status = 'suppressed')     AS suppressed_count,
    COUNT(*) FILTER (WHERE sla_due < NOW() AND status IN ('open','in_progress')) AS overdue_count,
    COUNT(*)                                          AS total_count,
    ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'resolved') / NULLIF(COUNT(*),0), 2) AS resolution_rate
FROM remediation_items;
