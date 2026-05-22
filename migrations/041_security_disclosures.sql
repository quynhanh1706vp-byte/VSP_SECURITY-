-- 041_security_disclosures.sql — bug bounty / VDP intake table.
--
-- Backs POST /api/v1/security/disclose. Each row is a researcher's
-- vulnerability report; the triage workflow owns transitioning rows
-- through the SLA-tracked phases:
--
--   submitted  → ack-due in 1 business day
--   acknowledged
--   triaged    → severity assigned, fix-by date set per VDP rubric
--   resolved   → fix shipped, researcher informed
--   disclosed  → coordinated public disclosure
--   duplicate / out-of-scope / not-an-issue (terminal states)
--
-- The SLA columns let the dashboard surface "X reports overdue for
-- triage" without scanning all rows.

CREATE TABLE IF NOT EXISTS security_disclosures (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Public-facing reference (e.g. "VSP-VDR-2026-0042"). Generated
  -- server-side once the row is acknowledged so duplicates can be
  -- merged before the researcher sees a number.
  public_ref      TEXT UNIQUE,
  -- Researcher contact — kept separate from users to avoid linking
  -- their identity to a tenant. May be anonymous (just an email).
  reporter_name   TEXT NOT NULL DEFAULT '',
  reporter_email  TEXT NOT NULL,
  reporter_handle TEXT NOT NULL DEFAULT '',
  -- Report content. Body capped at 64k client-side; we store the
  -- raw text for audit, the SHA-256 lets us de-dup obviously
  -- identical submissions before manual triage.
  title           TEXT NOT NULL,
  body            TEXT NOT NULL,
  body_sha256     TEXT NOT NULL,
  affected        TEXT NOT NULL DEFAULT '',
  cvss_v3         NUMERIC(3,1),
  -- Workflow state.
  status          TEXT NOT NULL DEFAULT 'submitted'
                    CHECK (status IN ('submitted','acknowledged','triaged',
                                      'resolved','disclosed',
                                      'duplicate','out_of_scope','not_an_issue')),
  severity        TEXT CHECK (severity IN ('critical','high','medium','low','none')),
  -- SLA tracking. ack_due_at and triage_due_at are computed at insert
  -- time from the submitted_at timestamp + the VDP-published SLAs;
  -- fix_due_at is set when severity is assigned.
  submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ack_due_at      TIMESTAMPTZ NOT NULL,
  triage_due_at   TIMESTAMPTZ NOT NULL,
  fix_due_at      TIMESTAMPTZ,
  acknowledged_at TIMESTAMPTZ,
  triaged_at      TIMESTAMPTZ,
  resolved_at     TIMESTAMPTZ,
  disclosed_at    TIMESTAMPTZ,
  -- Who on the security team handled this. NULL until ack.
  assigned_to     UUID,
  -- Free-form notes for the triage team; never returned to the
  -- researcher.
  internal_notes  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_disc_status ON security_disclosures(status, ack_due_at);
CREATE INDEX IF NOT EXISTS idx_disc_dedup ON security_disclosures(body_sha256);
