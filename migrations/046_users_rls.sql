-- 046_users_rls.sql — close cross-tenant SELECT path on the users table.
--
-- L6-A 2026-05-09: scripts/test-l6-db-integrity.sh phase 7.6 found
-- that 4 of 5 tenant-scoped tables (findings, runs, audit_log,
-- compliance_evidence) had RLS policies but `users` did not. A
-- privileged role bypassing the handler-layer tenant filter (e.g.
-- direct psql by an operator, or a future internal report query
-- forgetting WHERE tenant_id) could SELECT every user across every
-- tenant — including emails (PII) and roles.
--
-- Pattern matches existing policies — same vsp_current_tenant() helper,
-- same OR-NULL escape hatch for migrations / superuser maintenance.

ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Force RLS on the table owner too. Without FORCE, the owner role
-- (typically the app user) bypasses RLS — defeating the point.
ALTER TABLE users FORCE ROW LEVEL SECURITY;

-- Drop existing if migration is re-run.
DROP POLICY IF EXISTS tenant_isolation ON users;

CREATE POLICY tenant_isolation ON users
    USING (tenant_id = vsp_current_tenant() OR vsp_current_tenant() IS NULL);
