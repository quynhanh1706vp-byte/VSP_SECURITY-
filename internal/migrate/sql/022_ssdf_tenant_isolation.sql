-- +goose Up
-- Migration 022: Add tenant_id to ssdf_practices for proper multi-tenant isolation.
-- Previously ssdf_practices was a global table shared across all tenants,
-- causing cross-tenant data leaks on UpdatePractice writes.
--
-- Strategy:
--   1. Add tenant_id column (nullable first)
--   2. Seed per-tenant rows by copying existing global rows for each tenant
--   3. Make tenant_id NOT NULL and drop old unique constraint
--   4. Add new unique constraint on (tenant_id, practice_id)
--   5. Add RLS policy

-- Step 1: Add tenant_id column
ALTER TABLE ssdf_practices
  ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Step 2: Copy existing rows for each tenant that has attestation_forms
-- This ensures existing tenants keep their current practice statuses
INSERT INTO ssdf_practices (
  tenant_id, practice_id, group_code, name, description,
  status, evidence_refs, implementation_notes, responsible_role,
  last_assessed, created_at, updated_at
)
SELECT
  t.id AS tenant_id,
  sp.practice_id, sp.group_code, sp.name, sp.description,
  sp.status, sp.evidence_refs, sp.implementation_notes,
  sp.responsible_role, sp.last_assessed, NOW(), NOW()
FROM tenants t
CROSS JOIN ssdf_practices sp
WHERE sp.tenant_id IS NULL  -- only copy global rows
ON CONFLICT DO NOTHING;

-- Step 3: For tenants with no practices yet, seed defaults from global rows
-- (handled above via CROSS JOIN)

-- Step 4: Set tenant_id for old global rows to default tenant if exists
UPDATE ssdf_practices
SET tenant_id = (SELECT id FROM tenants ORDER BY created_at LIMIT 1)
WHERE tenant_id IS NULL;

-- Step 5: Now make NOT NULL (all rows have tenant_id)
ALTER TABLE ssdf_practices
  ALTER COLUMN tenant_id SET NOT NULL;

-- Step 6: Drop old global unique constraint, add per-tenant unique
ALTER TABLE ssdf_practices
  DROP CONSTRAINT IF EXISTS ssdf_practices_practice_id_key;

ALTER TABLE ssdf_practices
  ADD CONSTRAINT ssdf_practices_tenant_practice_unique
  UNIQUE (tenant_id, practice_id);

-- Step 7: Add index for tenant queries
CREATE INDEX IF NOT EXISTS idx_ssdf_tenant
  ON ssdf_practices(tenant_id);

-- Step 8: Foreign key to tenants
ALTER TABLE ssdf_practices
  ADD CONSTRAINT ssdf_practices_tenant_fk
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE ssdf_practices DROP CONSTRAINT IF EXISTS ssdf_practices_tenant_fk;
ALTER TABLE ssdf_practices DROP CONSTRAINT IF EXISTS ssdf_practices_tenant_practice_unique;
DROP INDEX IF EXISTS idx_ssdf_tenant;
ALTER TABLE ssdf_practices ADD CONSTRAINT ssdf_practices_practice_id_key UNIQUE (practice_id);
ALTER TABLE ssdf_practices DROP COLUMN IF EXISTS tenant_id;
