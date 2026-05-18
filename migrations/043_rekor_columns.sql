-- 043_rekor_columns.sql — add Rekor transparency-log coordinates to
-- slsa_provenance so we can dedup publish calls and surface the public
-- entry URL on the Trust Center.

ALTER TABLE slsa_provenance
  ADD COLUMN IF NOT EXISTS rekor_uuid          TEXT,
  ADD COLUMN IF NOT EXISTS rekor_log_index     BIGINT,
  ADD COLUMN IF NOT EXISTS rekor_published_at  TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_slsa_rekor
  ON slsa_provenance(rekor_uuid)
  WHERE rekor_uuid IS NOT NULL;
