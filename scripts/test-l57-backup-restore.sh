#!/usr/bin/env bash
# scripts/test-l57-backup-restore.sh — pg_dump round-trip integrity.
#
# Gated by L57_BACKUP=1 because pg_restore is destructive (it can
# truncate target schema). Real DR drill: pg_dump → drop schema →
# pg_restore → verify row count matches.
#
# In CI we use a SECOND temp database (vsp_l57_restore) and restore
# into it, NOT the live vsp_go. That way the production DB is never
# touched.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

if [[ "${L57_BACKUP:-0}" != "1" ]]; then
  _skip "57.0 backup-restore drill" "L57_BACKUP!=1 — destructive, gated"
  final_summary; exit 0
fi

if ! command -v pg_dump &>/dev/null || ! command -v pg_restore &>/dev/null; then
  _skip "57.0 pg_dump/pg_restore" "tools not in PATH"
  final_summary; exit 0
fi

# ── 57.1 pg_dump exits 0 on the live DB ──────────────────────────────────

phase_open "57.1 pg_dump succeeds on live DB"

DUMP=$(mktemp --suffix=.sql)
if pg_dump --format=custom -Z 0 -f "$DUMP" "$DB_DSN" 2>/dev/null; then
  SIZE=$(wc -c < "$DUMP" | tr -d ' ')
  _pass "57.1.1 pg_dump produced $SIZE-byte archive"
else
  _fail "57.1.1 pg_dump failed" "see pg_dump stderr; live DB may have invalid state"
  rm -f "$DUMP"
  final_summary; exit 0
fi

# ── 57.2 Tenant + audit_log row counts dumped ────────────────────────────

phase_open "57.2 Critical tables present in dump"

# pg_restore --list shows TOC. Verify it includes tenants + audit_log.
TOC=$(pg_restore --list "$DUMP" 2>/dev/null)
MISSING=()
for t in tenants audit_log findings runs; do
  if ! echo "$TOC" | grep -qE "TABLE DATA public $t\b|TABLE public $t\b"; then
    MISSING+=("$t")
  fi
done

if (( ${#MISSING[@]} == 0 )); then
  _pass "57.2.1 dump contains all critical tables (tenants, audit_log, findings, runs)"
else
  _fail "57.2.1 critical table missing from dump" "${MISSING[*]}"
fi

# ── 57.3 Round-trip into temp DB matches source row counts ──────────────

phase_open "57.3 Restore round-trip"

RESTORE_DB="vsp_l57_$(date +%s)"
psql -d "$DB_DSN" -c "CREATE DATABASE $RESTORE_DB;" 2>/dev/null || {
  _skip "57.3.0 create restore DB" "no permission to CREATE DATABASE"
  rm -f "$DUMP"
  final_summary; exit 0
}

# Restore. --no-owner to avoid role mismatch in CI.
RESTORE_DSN="${DB_DSN/$PGDATABASE/$RESTORE_DB}"
if pg_restore --no-owner --no-privileges -d "$RESTORE_DSN" "$DUMP" 2>&1 | head -5; then
  _pass "57.3.1 pg_restore completed"
else
  _fail "57.3.1 pg_restore failed" "see output above"
fi

# Row count comparison.
for table in tenants audit_log; do
  src=$(_psql_oneshot "SELECT COUNT(*) FROM $table;")
  dst=$(psql "$RESTORE_DSN" -tAc "SELECT COUNT(*) FROM $table;" 2>/dev/null | tr -d ' ')
  if [[ "$src" == "$dst" && -n "$src" ]]; then
    _pass "57.3.2 $table row count matches [$src]"
  else
    _fail "57.3.2 $table row count mismatch" "src=$src dst=$dst"
  fi
done

# Cleanup
psql -d "$DB_DSN" -c "DROP DATABASE $RESTORE_DB;" 2>/dev/null || true
rm -f "$DUMP"

# ── 57.4 audit_log hash chain verifies in the restored DB ────────────────

phase_open "57.4 audit_log chain intact after round-trip (informational)"

# Can't probe restored DB via the gateway (different DB), so this
# section is informational. Done in the destructive nightly drill.
_skip "57.4.1 chain verify on restored DB" \
  "requires standing up a gateway against the restored DB — out of scope for CI L57"

final_summary
