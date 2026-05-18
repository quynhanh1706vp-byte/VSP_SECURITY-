-- 039_data_residency.sql — per-tenant region binding for data
-- residency / sovereignty compliance.
--
-- Vietnam Decree 53/2022 Art. 26 requires personal data of Vietnamese
-- citizens to be stored on servers physically located in Vietnam (or
-- one of a small list of pre-approved foreign locations). Similar
-- regimes exist for EU (GDPR + national rulings on Schrems II
-- transfers), India (DPDP Act 2023), Russia (152-FZ), and several
-- US state laws.
--
-- Approach:
--   • Each tenant declares a primary region at onboarding (vn-1, eu-1,
--     us-1, etc.) and an optional "allow_egress_regions" list of
--     regions where its data MAY be processed (zero means "primary
--     only").
--   • The gateway exposes its own region via VSP_REGION env var. A
--     middleware compares the tenant's region/egress list to the
--     gateway's region; mismatch returns 451 Unavailable For Legal
--     Reasons (intentional — IETF RFC 7725).
--   • Every cross-region check is audit-logged so a regulator can
--     evidence that data did not leave the declared jurisdiction.

CREATE TABLE IF NOT EXISTS tenant_residency (
  tenant_id              UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  -- Primary region the tenant data lives in. Free-form region code
  -- (e.g. "vn-1", "vn-2", "eu-frankfurt", "us-east-1"); the gateway
  -- maps these to physical deployments via VSP_REGION.
  primary_region         TEXT NOT NULL,
  -- Optional list of regions where data may be processed in addition
  -- to the primary. Empty = strict residency (no egress).
  allow_egress_regions   TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  -- Legal basis for the residency choice. Free-text; surfaces in the
  -- compliance evidence panel for auditors.
  basis                  TEXT NOT NULL DEFAULT '',
  -- The tenant admin who confirmed the residency configuration
  -- (Decree 53/2022 wants signed acceptance from a responsible party).
  confirmed_by           UUID,
  confirmed_at           TIMESTAMPTZ,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit table for cross-region access denials. Keep separate from
-- audit_log to avoid bloat; this table is bounded by retention policy.
CREATE TABLE IF NOT EXISTS residency_violations (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  gateway_region    TEXT NOT NULL,
  expected_region   TEXT NOT NULL,
  request_path      TEXT NOT NULL,
  request_ip        TEXT,
  user_id           UUID,
  detected_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_residency_violations_tenant
  ON residency_violations(tenant_id, detected_at DESC);
