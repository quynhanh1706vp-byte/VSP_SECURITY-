#!/usr/bin/env bash
# scripts/test-l6-db-integrity.sh — L6 DB integrity invariants probe.
#
# Bash + SQL audit. Pre-flight: $DB_DSN exported.
#
# Each probe asserts a structural property the codebase MUST keep true.
# Drift here usually means: a migration left rows in a half-state, a
# concurrent writer raced against an INSERT/UPDATE, or a handler is
# computing a value that disagrees with what it stores.
#
# This complements L1-L5 (which test the API surface) by going UNDER
# the API and inspecting the DB the API is supposed to maintain. Real
# bug example sitting in this DB at start of L6: the audit-chain race
# left 29 corrupted rows (already fixed in L5). L6 catches the next
# one — whatever it is.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command psql jq

# assert_db_zero NAME SQL
# Runs SQL expected to return a single integer; passes when it's 0.
# Use for "no orphan rows", "no chain gaps" style invariants.
assert_db_zero() {
  local name="$1" sql="$2"
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  if ! command -v psql &>/dev/null; then
    _skip "$name" "psql not installed"; return
  fi
  local got
  got=$(_psql_oneshot "$sql")
  if [[ -z "$got" ]]; then got=0; fi
  if [[ "$got" == "0" ]]; then
    _pass "$name [count=0]"
  else
    _fail "$name" "SQL returned $got (expected 0)"
  fi
}

# ── 7.1 Foreign-key integrity ──────────────────────────────────────────────

phase_open "7.1 Foreign-key integrity — no orphan rows"

assert_db_zero "7.1.1 findings.run_id all reference real runs" \
  "SELECT count(*) FROM findings f
   WHERE NOT EXISTS (SELECT 1 FROM runs r WHERE r.id = f.run_id)"

assert_db_zero "7.1.2 findings.tenant_id all reference real tenants" \
  "SELECT count(*) FROM findings f
   WHERE NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id = f.tenant_id)"

assert_db_zero "7.1.3 runs.tenant_id all reference real tenants" \
  "SELECT count(*) FROM runs r
   WHERE NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id = r.tenant_id)"

assert_db_zero "7.1.4 audit_log.tenant_id all reference real tenants" \
  "SELECT count(*) FROM audit_log a
   WHERE NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id = a.tenant_id)"

assert_db_zero "7.1.5 users.tenant_id all reference real tenants" \
  "SELECT count(*) FROM users u
   WHERE NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id = u.tenant_id)"

assert_db_zero "7.1.6 compliance_evidence.tenant_id valid" \
  "SELECT count(*) FROM compliance_evidence e
   WHERE NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id = e.tenant_id)"

# Hot table (varies per deployment): poam_records → tenants. We can't
# wrap the query in CASE WHEN to_regclass(...) IS NULL because Postgres
# parses both branches up front and the missing-table reference errors
# at parse time. Probe existence first, then run the actual check.
POAM_EXISTS=$(_psql_oneshot "SELECT to_regclass('public.poam_records') IS NOT NULL")
if [[ "$POAM_EXISTS" == "t" ]]; then
  assert_db_zero "7.1.7 poam_records.tenant_id valid" \
    "SELECT count(*) FROM poam_records p
     WHERE NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id = p.tenant_id)"
else
  _skip "7.1.7 poam_records.tenant_id valid" "table absent in this deployment"
fi

# ── 7.2 Audit chain integrity ──────────────────────────────────────────────

phase_open "7.2 Audit chain — no gaps, no pending, ordering"

# 7.2.1: no row left in transient 'pending' state (would mean InsertAudit
# crashed mid-way after the L5 fix should have made this atomic).
assert_db_zero "7.2.1 no audit rows in 'pending' hash state" \
  "SELECT count(*) FROM audit_log WHERE hash = 'pending'"

# 7.2.2: every prev_hash either '' (genesis row per tenant) or matches
# the prior row's hash for the SAME tenant.
assert_db_zero "7.2.2 audit chain prev_hash references prior row hash" \
  "SELECT count(*) FROM (
     SELECT seq, tenant_id, prev_hash,
            LAG(hash) OVER (PARTITION BY tenant_id ORDER BY seq) AS expected_prev
     FROM audit_log
   ) x
   WHERE prev_hash IS NOT NULL
     AND prev_hash <> ''
     AND expected_prev IS NOT NULL
     AND prev_hash <> expected_prev"

# 7.2.3: seq is monotonic globally (it's a SERIAL — should be by
# definition; this catches the case where someone did a manual INSERT
# with an explicit seq).
assert_db_zero "7.2.3 audit_log.seq strictly increasing per insert order" \
  "SELECT count(*) FROM (
     SELECT seq, LAG(seq) OVER (ORDER BY seq) AS prev_seq
     FROM audit_log
   ) x
   WHERE prev_seq IS NOT NULL AND seq <= prev_seq"

# 7.2.4: tenants share a global sequence (audit_log.seq is global, not
# per-tenant). This is informational — assert there are no two rows with
# the same seq.
assert_db_zero "7.2.4 audit_log.seq unique" \
  "SELECT count(*) FROM (
     SELECT seq, count(*) AS c FROM audit_log GROUP BY seq HAVING count(*) > 1
   ) x"

# ── 7.3 Findings ↔ runs aggregate consistency ──────────────────────────────

phase_open "7.3 Findings ↔ runs aggregate"

# 7.3.1: runs.total_findings should match COUNT of findings rows for
# that run. Drift here means the runs row was updated optimistically
# without re-counting, or findings were inserted/deleted without
# touching the run row.
# Skip rows where stored=0 (legacy data where the count was never set
# by the pipeline writer). Drift on rows with a stored count >0 is a
# real bug.
assert_db_zero "7.3.1 runs.total_findings == count(findings) for completed runs" \
  "SELECT count(*) FROM (
     SELECT r.id, r.total_findings AS stored,
            (SELECT count(*) FROM findings f WHERE f.run_id = r.id) AS actual
     FROM runs r
     WHERE r.status = 'DONE'
   ) x
   WHERE stored <> actual AND stored > 0"

# 7.3.2: findings.tenant_id must equal the parent run's tenant_id (a
# finding cannot belong to a different tenant than its run).
assert_db_zero "7.3.2 findings.tenant_id == runs.tenant_id" \
  "SELECT count(*) FROM findings f
   JOIN runs r ON r.id = f.run_id
   WHERE f.tenant_id <> r.tenant_id"

# ── 7.4 Tenant scoping invariants ──────────────────────────────────────────

phase_open "7.4 Tenant scoping — no NULL where tenant required"

assert_db_zero "7.4.1 findings.tenant_id NOT NULL" \
  "SELECT count(*) FROM findings WHERE tenant_id IS NULL"

assert_db_zero "7.4.2 runs.tenant_id NOT NULL" \
  "SELECT count(*) FROM runs WHERE tenant_id IS NULL"

assert_db_zero "7.4.3 audit_log.tenant_id NOT NULL" \
  "SELECT count(*) FROM audit_log WHERE tenant_id IS NULL"

assert_db_zero "7.4.4 users.tenant_id NOT NULL" \
  "SELECT count(*) FROM users WHERE tenant_id IS NULL"

assert_db_zero "7.4.5 compliance_evidence.tenant_id NOT NULL" \
  "SELECT count(*) FROM compliance_evidence WHERE tenant_id IS NULL"

# ── 7.5 Time invariants ────────────────────────────────────────────────────

phase_open "7.5 Temporal — created_at sane"

assert_db_zero "7.5.1 no audit_log row from the future" \
  "SELECT count(*) FROM audit_log WHERE created_at > NOW() + INTERVAL '5 minutes'"

assert_db_zero "7.5.2 no run with finished_at < started_at" \
  "SELECT count(*) FROM runs
   WHERE finished_at IS NOT NULL AND started_at IS NOT NULL
     AND finished_at < started_at"

DSR_EXISTS=$(_psql_oneshot "SELECT to_regclass('public.data_subject_requests') IS NOT NULL")
if [[ "$DSR_EXISTS" == "t" ]]; then
  assert_db_zero "7.5.3 no DSR with completed_at < created_at" \
    "SELECT count(*) FROM data_subject_requests
     WHERE completed_at IS NOT NULL AND completed_at < created_at"
else
  _skip "7.5.3 no DSR with completed_at < created_at" "table absent"
fi

# ── 7.6 RLS sanity ─────────────────────────────────────────────────────────

phase_open "7.6 RLS — policies exist on tenant-scoped tables"

# Every tenant-scoped table SHOULD have a row-level-security policy
# defined. If RLS is off, even just checking pg_policies catches the
# regression where a table was added without a policy. Real bug pattern:
# Sprint 12 added compliance_evidence; if its CREATE POLICY was missed
# the API would still work but a privileged-user SELECT could see all
# tenants.
for tbl in findings runs audit_log users compliance_evidence; do
  POL_COUNT=$(_psql_oneshot "SELECT count(*) FROM pg_policies WHERE tablename = '$tbl';")
  if [[ "$POL_COUNT" -ge 1 ]]; then
    _pass "7.6.$tbl has $POL_COUNT RLS polic(y/ies)"
  else
    _fail "7.6.$tbl RLS missing" "table $tbl has 0 policies in pg_policies"
  fi
done

# ── 7.7 Data-quality invariants ────────────────────────────────────────────

phase_open "7.7 Data quality — no anomalous rows"

# 7.7.1: every finding has a non-empty severity. Empty/NULL severity
# breaks the gate scoring (Score iterates by case sev).
assert_db_zero "7.7.1 findings.severity always set" \
  "SELECT count(*) FROM findings WHERE COALESCE(severity, '') = ''"

# 7.7.2: severity values are one of the allowed enum strings.
assert_db_zero "7.7.2 findings.severity in {CRITICAL,HIGH,MEDIUM,LOW,INFO,TRACE}" \
  "SELECT count(*) FROM findings
   WHERE severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','TRACE')"

# 7.7.3: no completed run with status='DONE' but tools_done < tools_total.
# The pipeline should bump tools_done as each scanner finishes.
assert_db_zero "7.7.3 DONE runs have tools_done = tools_total" \
  "SELECT count(*) FROM runs
   WHERE status = 'DONE' AND tools_done < tools_total"

# 7.7.4: duplicate fingerprints within the SAME run = a scanner emitted
# the same finding twice. Schema has the fingerprint as a generated
# column, so any duplicate is a real (likely benign but worth logging)
# data quality issue.
assert_db_zero "7.7.4 no duplicate fingerprints within a single run" \
  "SELECT count(*) FROM (
     SELECT run_id, fingerprint, count(*) AS c
     FROM findings GROUP BY run_id, fingerprint HAVING count(*) > 1
   ) x"

# ── final ──────────────────────────────────────────────────────────────────

final_summary
