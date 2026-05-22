-- 032_slsa_l3_signed.sql — SLSA L3 readiness: cryptographic signing of
-- provenance statements + per-run linkage.
--
-- L2 → L3 gap closed by this migration:
--   • signature column captures the ECDSA P-256 signature over the
--     canonical statement JSON, enabling third-party verification.
--   • signing_key_id records which key signed (for rotation / revocation
--     workflows).
--   • run_id FK links each provenance to the scan run that produced it,
--     so the existing /runs/{id} endpoint can offer "view attestation".
--   • dsse_envelope stores the DSSE (Dead Simple Signing Envelope, in-toto
--     attestation v1) JSON, which is the format Sigstore / Rekor accept.
--
-- The "isolated builder + ephemeral key" L3 requirement is gated on the
-- *deployment* — see docs/SLSA_L3_RUNBOOK.md for the GHA/Tekton path.

ALTER TABLE slsa_provenance
  ADD COLUMN IF NOT EXISTS run_id          UUID,
  ADD COLUMN IF NOT EXISTS signature       TEXT,
  ADD COLUMN IF NOT EXISTS signing_key_id  TEXT,
  ADD COLUMN IF NOT EXISTS dsse_envelope   JSONB,
  ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_slsa_run ON slsa_provenance(run_id) WHERE run_id IS NOT NULL;
