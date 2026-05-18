-- 036_data_subject_requests.sql — DSAR + right-to-erasure tracking.
--
-- Two regulatory hooks:
--   • GDPR Art. 15  (right of access)         → data export request
--   • GDPR Art. 17  (right to erasure)        → tenant deletion request
--   • PDPA Decree 13/2023 (Vietnam) Arts. 9-12 → both
--
-- Erasure is async with a 30-day grace window — allows mistake recovery
-- and matches GDPR's "without undue delay" interpretation in EDPB
-- Guidelines 1/2022. The grace can be shortened (legal hold, regulator
-- order) by setting scheduled_at via admin tooling.

CREATE TABLE IF NOT EXISTS data_subject_requests (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  -- Who triggered the request. user_id is who pushed the button; for
  -- erasure that's typically the tenant admin acting on a customer ask.
  requested_by    UUID,
  kind            TEXT NOT NULL CHECK (kind IN ('export','erasure')),
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','processing','ready',
                                      'completed','cancelled','failed')),
  -- Erasure: scheduled_at is when the actual delete fires. Default is
  -- NOW() + 30 days but admins / legal can adjust.
  scheduled_at    TIMESTAMPTZ,
  -- Export: result_url points to the generated artefact (signed URL or
  -- /api/v1/data/exports/{id}/download path). NULL until status='ready'.
  result_url      TEXT,
  -- Optional reason / customer reference. Free-text, capped at 1024 chars.
  notes           TEXT NOT NULL DEFAULT '',
  -- For erasure: a SHA-256 of the deletion-confirmation token sent to
  -- the user. They confirm by providing the plaintext, preventing a
  -- compromised admin session from instantly purging without external
  -- verification.
  confirm_hash    TEXT NOT NULL DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_dsr_tenant_status
  ON data_subject_requests(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_dsr_scheduled
  ON data_subject_requests(scheduled_at)
  WHERE kind = 'erasure' AND status IN ('pending','processing');
