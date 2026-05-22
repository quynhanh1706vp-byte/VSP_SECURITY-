-- 030_compliance_evidence.sql — file storage for compliance artifacts
-- (SSP, FIPS-199, AO-Approval letters, penetration test reports, etc.)
--
-- Closes the "compliance evidence files 404" gap: the P4 panel referenced
-- artifacts like "SSP-Section-1.pdf" but had no storage backend, so clicking
-- a task's evidence link returned 404. Now files persist in this table and
-- are served via /api/v1/compliance/evidence/{id} with tenant scoping.
--
-- Storage choice: bytea in Postgres rather than S3 / filesystem.
--   Pros: zero ops, transactional with audit_log, automatic backup with DB
--   Cons: bloats DB; not suitable for files >10 MB (enforced at handler)
-- For air-gapped DoD deployments this is the right trade-off; for cloud
-- deployments a future migration can move blobs to S3 keeping metadata here.

CREATE TABLE IF NOT EXISTS compliance_evidence (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  -- The compliance object this evidence proves. Free-form so it can reference
  -- a NIST control id (AC-2), an RMF task id (C-1), a TT17 chapter, etc.
  control_id   TEXT NOT NULL,
  -- Original upload filename (display-only, never used for filesystem path).
  filename     TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  size_bytes   INT  NOT NULL CHECK (size_bytes >= 0),
  -- SHA-256 of blob; lets clients verify integrity post-download and lets us
  -- detect duplicate uploads cheaply.
  sha256       TEXT NOT NULL,
  uploaded_by  UUID,
  uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  notes        TEXT NOT NULL DEFAULT '',
  blob         BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS compliance_evidence_tenant_control_idx
  ON compliance_evidence (tenant_id, control_id, uploaded_at DESC);

-- Distinct hash per tenant prevents storing the same file twice; uploading
-- the same content updates the existing row's metadata instead.
CREATE UNIQUE INDEX IF NOT EXISTS compliance_evidence_dedup_idx
  ON compliance_evidence (tenant_id, sha256);
