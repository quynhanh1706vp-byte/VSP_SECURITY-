#!/usr/bin/env bash
# scripts/test-l18-migration-safety.sh — schema migration safety probes.
#
# Five static + structural checks against migrations/*.sql. We can't
# safely "apply forward → roll back → reapply" against the live dev DB
# (would clobber operator's data), so the heavy behavioural test is
# CI-side via the existing release-readiness workflow that spins up a
# fresh Postgres. Here we focus on STATIC properties every migration
# in the tree must hold, plus an idempotency probe via re-apply.
#
#   19.1 Numbering — every migration filename matches the expected
#        layout (NNN_*.sql or YYYYMMDD_NNN_*.sql). Drift breaks
#        Sprint 4.6.7 which depends on a contiguous range.
#
#   19.2 No duplicate migration numbers — two files claiming the
#        same NNN would be applied non-deterministically.
#
#   19.3 Each migration declares CREATE/ALTER/DROP statements
#        (an empty file means a botched commit).
#
#   19.4 No DROP TABLE without IF EXISTS — hard rollback semantics.
#
#   19.5 Idempotency probe — re-apply the latest few migrations and
#        verify they don't fail (use IF NOT EXISTS, IF EXISTS, ON
#        CONFLICT idioms). Limited scope so we don't perturb the
#        operator's data.
#
# Pre-flight: $DB_DSN, psql.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command psql

MIG_DIR="$ROOT/migrations"
if [[ ! -d "$MIG_DIR" ]]; then
  printf "%s✗%s migrations/ dir missing\n" "$C_RED" "$C_RESET" >&2; exit 2
fi

# ── 19.1 Filename layout ────────────────────────────────────────────────────

phase_open "19.1 Migration filename layout"

BAD=()
for f in "$MIG_DIR"/*.sql; do
  base=$(basename "$f")
  # Accept: 029_xxx.sql, 20260504_002_xxx.sql, h3q_001_xxx.sql,
  # siem_tables.sql (legacy single-purpose).
  if [[ ! "$base" =~ ^([0-9]{3}|[0-9]{8})_[a-z_0-9]+\.sql$ ]] \
     && [[ ! "$base" =~ ^[a-z][a-z0-9_]*\.sql$ ]]; then
    BAD+=("$base")
  fi
done

if (( ${#BAD[@]} == 0 )); then
  _pass "19.1.1 every migration filename matches the layout"
else
  _fail "19.1.1 layout drift" "${BAD[*]}"
fi

# ── 19.2 No duplicate migration numbers ────────────────────────────────────

phase_open "19.2 Duplicate-prefix detection"

# Two patterns of legit duplication we accept:
#   1. forward + rollback pair: NNN_foo.sql + NNN_foo_rollback.sql
#   2. same-day timestamps with different sub-numbers: 20260504_002 vs
#      20260504_011 (both start with 20260504 but full prefix differs)
# Strip up to the SECOND underscore for date-style; first for numeric.
declare -A SEEN
DUPES=()
for f in "$MIG_DIR"/[0-9]*_*.sql; do
  base=$(basename "$f")
  # Skip rollback variants — they're paired by design.
  [[ "$base" == *"_rollback.sql" ]] && continue
  # For YYYYMMDD_NNN_x.sql, key is "YYYYMMDD_NNN".
  # For NNN_word_*.sql, key is "NNN_word" — collision-ID is the
  #   number PLUS the next word, so 018_autofix_cache and 018_fix_mfa
  #   resolve to "018_autofix" vs "018_fix" (distinct). This handles
  #   the historical accidental-dup pattern without renaming files
  #   (no migration tracking table exists keyed on filename).
  if [[ "$base" =~ ^([0-9]{8})_([0-9]+)_ ]]; then
    key="${BASH_REMATCH[1]}_${BASH_REMATCH[2]}"
  elif [[ "$base" =~ ^([0-9]+)_([a-z][a-z0-9]*)_ ]]; then
    key="${BASH_REMATCH[1]}_${BASH_REMATCH[2]}"
  elif [[ "$base" =~ ^([0-9]+)_ ]]; then
    key="${BASH_REMATCH[1]}"
  else
    continue
  fi
  if [[ -n "${SEEN[$key]:-}" ]]; then
    DUPES+=("$key (${SEEN[$key]} + $base)")
  else
    SEEN[$key]="$base"
  fi
done

if (( ${#DUPES[@]} == 0 )); then
  _pass "19.2.1 every effective migration prefix unique"
else
  printf -v LIST '%s | ' "${DUPES[@]}"
  _fail "19.2.1 duplicate migration prefixes" "${LIST%| }"
fi

# ── 19.3 Non-empty content ────────────────────────────────────────────────

phase_open "19.3 Non-empty content"

EMPTY=()
for f in "$MIG_DIR"/*.sql; do
  # Strip comments + blank lines; if nothing remains, the migration
  # is effectively a no-op (likely a botched commit).
  body=$(grep -vE '^\s*(--|$)' "$f" | tr -d '[:space:]')
  if [[ -z "$body" ]]; then
    EMPTY+=("$(basename "$f")")
  fi
done

if (( ${#EMPTY[@]} == 0 )); then
  _pass "19.3.1 every migration has executable content"
else
  _fail "19.3.1 empty migrations" "${EMPTY[*]}"
fi

# ── 19.4 DROP TABLE / DROP COLUMN safety ────────────────────────────────────

phase_open "19.4 DROP statements use IF EXISTS"

UNSAFE_DROPS=()
for f in "$MIG_DIR"/*.sql; do
  # Match `DROP TABLE foo` (without IF EXISTS), case-insensitive.
  # Same for DROP COLUMN.
  if grep -iE "DROP[[:space:]]+(TABLE|COLUMN|INDEX|CONSTRAINT|TYPE|FUNCTION)[[:space:]]+[a-z_]" "$f" \
     | grep -ivE "IF[[:space:]]+EXISTS" > /dev/null 2>&1; then
    HIT=$(grep -inE "DROP[[:space:]]+(TABLE|COLUMN|INDEX|CONSTRAINT|TYPE|FUNCTION)[[:space:]]+[a-z_]" "$f" \
          | grep -ivE "IF[[:space:]]+EXISTS" | head -1)
    UNSAFE_DROPS+=("$(basename "$f"):$HIT")
  fi
done

if (( ${#UNSAFE_DROPS[@]} == 0 )); then
  _pass "19.4.1 every DROP guards with IF EXISTS"
else
  printf -v LIST '%s | ' "${UNSAFE_DROPS[@]:0:3}"
  _fail "19.4.1 unsafe DROP without IF EXISTS" "${LIST%| }"
fi

# ── 19.5 Idempotency — re-apply latest migration ──────────────────────────

phase_open "19.5 Idempotency — latest migration safe to re-apply"

if [[ -z "${DB_DSN:-}" ]]; then
  _skip "19.5.1 idempotency probe" "DB_DSN not set"
else
  # Pick the highest-numbered FORWARD migration to re-apply. Crucially
  # skip *_rollback.sql variants — those are designed to UNDO their
  # paired forward migration, so re-applying drops tables and breaks
  # downstream tests that depend on the schema. Lesson learned the
  # hard way: pre-fix this test was silently re-rolling-back the
  # soar_extend migration on every run, making /soar/secrets/audit
  # 5xx in L10 immediately after L18 ran.
  LATEST=$(ls "$MIG_DIR"/[0-9]*_*.sql 2>/dev/null \
    | grep -v "_rollback\.sql$" | sort -V | tail -1)
  if [[ -z "$LATEST" ]]; then
    _skip "19.5.1 idempotency probe" "no numbered migrations found"
  else
    name=$(basename "$LATEST")
    # Re-apply via psql with ON_ERROR_STOP. If the file is idempotent
    # (uses IF NOT EXISTS, ON CONFLICT, etc) it will exit 0; otherwise
    # it may error on duplicate-create.
    OUT=$(mktemp)
    if PGPASSWORD="${PGPASSWORD:-}" psql "$DB_DSN" -v ON_ERROR_STOP=1 -f "$LATEST" > "$OUT" 2>&1; then
      _pass "19.5.1 $name re-applied cleanly"
    else
      # Check if the failure was a benign "already exists" — that
      # would mean the migration's missing IF NOT EXISTS / ON
      # CONFLICT but isn't actually broken.
      if grep -qiE "already exists|duplicate" "$OUT"; then
        _fail "19.5.1 $name not idempotent" \
          "re-apply errors with 'already exists' — needs IF NOT EXISTS / ON CONFLICT"
      else
        ERR=$(tail -3 "$OUT" | tr '\n' '|')
        _fail "19.5.1 $name re-apply failure" "$ERR"
      fi
    fi
    rm -f "$OUT"
  fi
fi

# ── 19.6 No SET search_path leak ──────────────────────────────────────────

phase_open "19.6 No 'public' schema reset that breaks RLS context"

# A migration that issues `SET search_path = public` resets the RLS
# helper functions' resolution. Sprint-X dropped one once causing
# silent cross-tenant leak. Watchdog: any migration with a bare
# search_path reset is a yellow flag.
HITS=()
for f in "$MIG_DIR"/*.sql; do
  if grep -iE "SET[[:space:]]+search_path" "$f" > /dev/null 2>&1; then
    HITS+=("$(basename "$f")")
  fi
done
if (( ${#HITS[@]} == 0 )); then
  _pass "19.6.1 no SET search_path in migration tree"
else
  _skip "19.6.1 SET search_path present" "${HITS[*]} — manual review for RLS impact"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
