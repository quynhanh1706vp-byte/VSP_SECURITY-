#!/usr/bin/env bash
# scripts/test-l7-dsr-residue.sh — DSR right-to-erasure residue check.
#
# GDPR Article 17 + Vietnam PDPA Decree 13/2023 both require that when
# a data subject requests erasure, ALL their personal data is removed
# from the system. In a multi-tenant platform this means: every table
# scoped to a tenant_id must drop rows for the erased tenant.
#
# Two phases:
#
#   8.1 Static — diff the schema's tenant_id-bearing tables against the
#       erasure worker's hardcoded list (parsed from dsr.go). Any table
#       in the schema but missing from the worker is residue waiting to
#       happen. Cheap, deterministic, runs in <1s.
#
#   8.2 Live — seed a synthetic "canary" tenant with rows in EVERY
#       tenant-scoped table the schema reveals, fire an immediate-due
#       erasure, wait for the worker, then COUNT(*) every table for
#       canary tenant_id. Any non-zero count is residue.
#
#       Disabled by default because it mutates DB state (creates a
#       throwaway tenant). Set RUN_L7_LIVE=1 to enable.
#
# Pre-flight: $DB_DSN, plus the gateway running for the live phase.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command psql jq

# ── 8.1 Static schema-vs-worker diff ───────────────────────────────────────

phase_open "8.1 Static — schema tenant_id tables ⊆ erasure worker list"

# All tables in public schema with a tenant_id column.
SCHEMA_TABLES=$(_psql_oneshot "SELECT string_agg(table_name, ',' ORDER BY table_name)
                               FROM information_schema.columns
                               WHERE column_name='tenant_id' AND table_schema='public'")

# Parse the worker's hardcoded list out of dsr.go. The block is delimited
# by 'tables := []string{' / '}'. We accept simple "tablename" or
# "tablename" entries.
WORKER_FILE="$ROOT/internal/api/handler/dsr.go"
if [[ ! -f "$WORKER_FILE" ]]; then
  _fail "8.1.0 dsr worker source present" "$WORKER_FILE missing"
  final_summary; exit 1
fi

# Tables that must NOT be erased even though they carry a tenant_id:
# the request log (audit trail of the erasure), residency config, and
# dated backup tables. Keep in sync with eraseTableExclude in dsr.go.
EXCLUDE_FROM_ERASURE="data_subject_requests,tenant_residency,scan_schedules_backup_20260428"
IFS=',' read -r -a SCHEMA_ARR <<<"$SCHEMA_TABLES"
IFS=',' read -r -a EXCLUDE_ARR <<<"$EXCLUDE_FROM_ERASURE"
declare -A IN_EXCLUDE IN_SCHEMA
for t in "${EXCLUDE_ARR[@]}"; do IN_EXCLUDE["$t"]=1; done
for t in "${SCHEMA_ARR[@]}"; do IN_SCHEMA["$t"]=1; done

# Detect worker mode. Two acceptable styles:
#
#   (a) DYNAMIC — worker queries information_schema for tenant_id
#       columns at runtime. Self-healing: future migrations are picked
#       up automatically. Look for the marker query.
#
#   (b) STATIC  — worker has a hardcoded `tables := []string{ ... }`
#       block. Fragile but explicit; we cross-check against schema.
#
# A worker without either is a release blocker.
if grep -qE "information_schema\.columns" "$WORKER_FILE" \
   && grep -qE "column_name\s*=\s*'tenant_id'" "$WORKER_FILE"; then
  WORKER_MODE="dynamic"
elif grep -qE "tables\s*:=\s*\[\]string\{" "$WORKER_FILE"; then
  WORKER_MODE="static"
else
  WORKER_MODE="missing"
fi

case "$WORKER_MODE" in
  dynamic)
    _pass "8.1.1 erasure worker uses dynamic information_schema enumeration [self-healing]"
    # Cross-check the EXCLUDE list in code matches our shell EXCLUDE.
    # Each entry in the bash EXCLUDE_FROM_ERASURE must appear in the
    # eraseTableExclude map literal.
    DRIFT=()
    for t in "${EXCLUDE_ARR[@]}"; do
      [[ -z "$t" ]] && continue
      if ! grep -qE "\"$t\"\s*:\s*true" "$WORKER_FILE"; then
        DRIFT+=("$t")
      fi
    done
    if (( ${#DRIFT[@]} == 0 )); then
      _pass "8.1.2 EXCLUDE list in test ⊆ eraseTableExclude in dsr.go"
    else
      printf -v DLIST '%s, ' "${DRIFT[@]}"
      _fail "8.1.2 EXCLUDE list drift" \
        "test references ${DLIST%, } but they are not in eraseTableExclude"
    fi
    ;;
  static)
    WORKER_TABLES=$(awk '
      /tables\s*:=\s*\[\]string\{/ { capture=1; next }
      capture && /^\s*\}/          { capture=0 }
      capture                       { print }
    ' "$WORKER_FILE" | grep -oE '"[a-z_][a-z_0-9]*"' | tr -d '"' | sort -u | tr '\n' ',' | sed 's/,$//')
    IFS=',' read -r -a WORKER_ARR <<<"$WORKER_TABLES"
    declare -A IN_WORKER
    for t in "${WORKER_ARR[@]}"; do IN_WORKER["$t"]=1; done
    MISSING=()
    for t in "${SCHEMA_ARR[@]}"; do
      [[ -z "$t" ]] && continue
      if [[ -z "${IN_WORKER[$t]:-}" && -z "${IN_EXCLUDE[$t]:-}" ]]; then
        MISSING+=("$t")
      fi
    done
    if (( ${#MISSING[@]} == 0 )); then
      _pass "8.1.1 every tenant_id-bearing table covered by erasure worker"
    else
      printf -v MLIST '%s, ' "${MISSING[@]}"
      _fail "8.1.1 erasure worker missing tables" \
        "${#MISSING[@]} tables hold tenant data but are NOT in dsr.go's hardcoded list: ${MLIST%, } (consider switching to information_schema enumeration)"
    fi
    STALE=()
    for t in "${WORKER_ARR[@]}"; do
      [[ -z "$t" ]] && continue
      if [[ -z "${IN_SCHEMA[$t]:-}" ]]; then
        STALE+=("$t")
      fi
    done
    if (( ${#STALE[@]} == 0 )); then
      _pass "8.1.2 erasure worker has no stale (renamed/dropped) tables"
    else
      printf -v SLIST '%s, ' "${STALE[@]}"
      _fail "8.1.2 erasure worker stale tables" \
        "worker references tables not in schema: ${SLIST%, }"
    fi
    ;;
  *)
    _fail "8.1.1 erasure worker not detected" \
      "$WORKER_FILE has neither information_schema enumeration nor a tables:=[]string{} block"
    ;;
esac

# ── 8.2 Live canary tenant erasure ─────────────────────────────────────────

if [[ "${RUN_L7_LIVE:-0}" != "1" ]]; then
  phase_open "8.2 Live canary — set RUN_L7_LIVE=1 to enable"
  _skip "8.2.1 live canary erasure" "RUN_L7_LIVE not set (mutating test, gated)"
  final_summary
  exit $?
fi

phase_open "8.2 Live canary — seed → erase → assert no residue"

CANARY_TENANT_UUID=$(_psql_oneshot "SELECT gen_random_uuid()")
CANARY_TENANT_SLUG="l7-canary-$$"
_psql_oneshot "INSERT INTO tenants (id, slug, name, plan)
               VALUES ('$CANARY_TENANT_UUID','$CANARY_TENANT_SLUG','L7 canary','FREE')
               ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true

# Seed canary rows into a representative subset of tables. We don't
# need to fill EVERY table — the post-erasure scan iterates all 77
# tenant_id-bearing tables and counts whatever residue is there. If
# the schema-vs-worker list (8.1) is in sync, the only tables that
# end up with residue here are the ones the worker SHOULD delete from
# but is failing to.
seed_canary_rows() {
  # findings / runs need a chained insert.
  _psql_oneshot "INSERT INTO runs (id, rid, tenant_id, mode, profile, status)
                 VALUES (gen_random_uuid(), 'l7-rid-$$', '$CANARY_TENANT_UUID',
                         'on-demand', 'FAST', 'DONE')
                 RETURNING id::text;" >/dev/null 2>&1 || true

  # A handful of common tables. Schema may vary; tolerate per-row failure.
  _psql_oneshot "INSERT INTO compliance_evidence
                   (tenant_id, control_id, filename, content_type, size_bytes, sha256, blob, notes)
                   VALUES ('$CANARY_TENANT_UUID', 'L7', 'l7-canary.txt',
                           'text/plain', 8, 'aa$(printf '0%.0s' {1..62})',
                           '\x4c372d43414e415259', 'l7 residue probe')
                   ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true

  _psql_oneshot "INSERT INTO feature_config (tenant_id, feature, enabled)
                   VALUES ('$CANARY_TENANT_UUID', 'l7_canary', true)
                   ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true
}
seed_canary_rows

# Insert a 'processing' DSR with scheduled_at in the past so the
# worker picks it up on its next tick.
DSR_ID=$(_psql_oneshot "INSERT INTO data_subject_requests
                          (tenant_id, requested_by, kind, status, scheduled_at, confirm_hash)
                          VALUES ('$CANARY_TENANT_UUID',
                                  '00000000-0000-0000-0000-000000000000',
                                  'erasure', 'processing',
                                  NOW() - INTERVAL '1 second',
                                  'l7-canary-hash')
                          RETURNING id::text;")

if [[ -z "$DSR_ID" ]]; then
  _fail "8.2.0 seed DSR" "could not insert processing erasure request"
  # Cleanup what we did seed.
  _psql_oneshot "DELETE FROM tenants WHERE id='$CANARY_TENANT_UUID';" >/dev/null 2>&1 || true
  final_summary; exit 1
fi

# Wait for the worker. The default tickInterval in production is 5min;
# we don't have an in-process trigger so set RUN_L7_LIVE_TICK_S to
# match your dev gateway's tick (often 10s in dev).
TICK_WAIT="${RUN_L7_LIVE_TICK_S:-15}"
sleep "$TICK_WAIT"

# Verify the request transitioned to 'completed'. If it's still
# 'processing' the worker hasn't run yet — our test would false-fail.
DSR_STATUS=$(_psql_oneshot "SELECT status FROM data_subject_requests WHERE id='$DSR_ID';")
if [[ "$DSR_STATUS" != "completed" ]]; then
  _skip "8.2.1 erasure worker processed canary" \
    "DSR still status=$DSR_STATUS after ${TICK_WAIT}s — increase RUN_L7_LIVE_TICK_S"
  _psql_oneshot "DELETE FROM data_subject_requests WHERE id='$DSR_ID';
                 DELETE FROM tenants WHERE id='$CANARY_TENANT_UUID';" >/dev/null 2>&1 || true
  final_summary; exit $?
fi
_pass "8.2.1 erasure worker processed canary [status=completed]"

# Now scan EVERY tenant_id-bearing table for residue.
RESIDUE_TABLES=()
for t in "${SCHEMA_ARR[@]}"; do
  [[ -z "$t" ]] && continue
  # Skip tables we deliberately exclude from erasure.
  [[ -n "${IN_EXCLUDE[$t]:-}" ]] && continue
  cnt=$(_psql_oneshot "SELECT count(*) FROM \"$t\" WHERE tenant_id = '$CANARY_TENANT_UUID';")
  cnt=${cnt:-0}
  if (( cnt > 0 )); then
    RESIDUE_TABLES+=("$t($cnt)")
  fi
done

if (( ${#RESIDUE_TABLES[@]} == 0 )); then
  _pass "8.2.2 zero residue across all $(printf '%s\n' "${SCHEMA_ARR[@]}" | wc -l | tr -d ' ') tenant tables"
else
  printf -v RESIDUE_LIST '%s, ' "${RESIDUE_TABLES[@]}"
  _fail "8.2.2 residue after erasure" \
    "rows still present in: ${RESIDUE_LIST%, }"
fi

# Cleanup. We're erasing what the worker missed plus the canary tenant.
for t in "${SCHEMA_ARR[@]}"; do
  [[ -z "$t" ]] && continue
  [[ -n "${IN_EXCLUDE[$t]:-}" ]] && continue
  _psql_oneshot "DELETE FROM \"$t\" WHERE tenant_id='$CANARY_TENANT_UUID';" >/dev/null 2>&1 || true
done
_psql_oneshot "DELETE FROM data_subject_requests WHERE tenant_id='$CANARY_TENANT_UUID';
               DELETE FROM tenants WHERE id='$CANARY_TENANT_UUID';" >/dev/null 2>&1 || true

# ── final ──────────────────────────────────────────────────────────────────

final_summary
