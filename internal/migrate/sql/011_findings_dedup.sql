-- +goose Up
-- +goose StatementBegin

-- 1. Add fingerprint column for deduplication
ALTER TABLE findings ADD COLUMN IF NOT EXISTS
    fingerprint TEXT GENERATED ALWAYS AS (
        md5(coalesce(tool,'') || '|' || coalesce(rule_id,'') || '|' ||
            coalesce(path,'') || '|' || coalesce(line_num::text,'0'))
    ) STORED;

-- 2. Unique constraint per run: same tool+rule+path+line = duplicate
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
    ON findings(run_id, fingerprint);

-- 3. Add triggered_by for audit trail (who/what started the scan)
ALTER TABLE runs ADD COLUMN IF NOT EXISTS triggered_by TEXT DEFAULT 'scheduler';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS policy_version TEXT DEFAULT 'v1';

-- 4. Add reason_code to runs for gate decision audit
ALTER TABLE runs ADD COLUMN IF NOT EXISTS gate_reason TEXT;

-- 5. min_score default: 70 (NIST SP 800-53 baseline)
UPDATE policy_rules SET min_score = 70 WHERE min_score = 0 OR min_score IS NULL;
ALTER TABLE policy_rules ALTER COLUMN min_score SET DEFAULT 70;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_findings_dedup;
ALTER TABLE findings DROP COLUMN IF EXISTS fingerprint;
ALTER TABLE runs DROP COLUMN IF EXISTS triggered_by;
ALTER TABLE runs DROP COLUMN IF EXISTS policy_version;
ALTER TABLE runs DROP COLUMN IF EXISTS gate_reason;
ALTER TABLE policy_rules ALTER COLUMN min_score SET DEFAULT 0;
-- +goose StatementEnd
