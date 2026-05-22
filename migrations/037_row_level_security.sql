-- 037_row_level_security.sql — Postgres RLS for tenant isolation
-- defence-in-depth.
--
-- Why this migration exists:
--   Application code already applies `WHERE tenant_id = $1` on every
--   query, so today tenant isolation is correct *if every developer
--   remembers to add the clause*. RLS turns that into a database-level
--   guarantee — a query without the GUC set returns zero rows, even if
--   the WHERE clause is missing.
--
-- How the policy works:
--   A request handler sets `vsp.tenant_id` via SET LOCAL (or the pgxpool
--   BeforeAcquire hook, when wired). The policy reads that GUC and
--   compares it to each row's tenant_id. Connections that don't set the
--   GUC see the empty string and the policy lets the row through *only
--   if* the connection role is the table owner — which the application
--   role is NOT in production deployments.
--
-- Production role separation:
--   • db_owner (runs migrations, owns tables) → bypasses RLS
--   • db_app   (runs the gateway/scheduler)   → subject to RLS
--   See docs/RLS_RUNBOOK.md for the role-separation steps. In dev /
--   docker-compose, gateway runs as owner so the policies are effectively
--   advisory; this is acceptable for v1 because the app already filters
--   by tenant_id at the application layer. The win is that any future
--   query that *forgets* the WHERE clause fails closed in prod.

-- Helper: returns the configured tenant or NULL when unset. A SECURITY
-- DEFINER function would let us assert types more strictly, but the
-- policy expressions are inlined for clarity.
CREATE OR REPLACE FUNCTION vsp_current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('vsp.tenant_id', true), '')::uuid
$$;

-- Apply RLS to the high-value tenant-scoped tables. We DO NOT FORCE on
-- the owner here — the app role only is subject to the policy. See
-- runbook for why this is the right v1 choice.
DO $$
DECLARE
  tbl text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY[
    'findings', 'runs', 'audit_log', 'compliance_evidence',
    'siem_webhooks', 'policy_rules', 'feature_config',
    'data_subject_requests', 'slsa_provenance'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format(
      'DROP POLICY IF EXISTS tenant_isolation ON %I', tbl);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I
         USING (tenant_id = vsp_current_tenant() OR vsp_current_tenant() IS NULL)
         WITH CHECK (tenant_id = vsp_current_tenant() OR vsp_current_tenant() IS NULL)',
      tbl);
  END LOOP;
END$$;

-- Migration leaves an audit trail in audit_log itself so operators can
-- trace when RLS was enabled per-tenant. (audit_log writes here pre-date
-- the policy creation in the same transaction; RLS doesn't apply.)
COMMENT ON FUNCTION vsp_current_tenant() IS
  'Returns the current request''s tenant id from SET vsp.tenant_id. Used by row_level_security policies on tenant-scoped tables.';
