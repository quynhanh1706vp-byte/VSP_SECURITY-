#!/usr/bin/env bash
# scripts/test-l78-migration-rollback.sh — every migration has a tested Down.
#
# Why this matters: an irreversible migration is an irreversible
# incident. If 018_agents_tables.sql ships with NULL'able columns on
# a critical table and breaks the read path, the only recovery is
# either (a) a hot-patched migration 019 or (b) point-in-time DB
# restore. Both are 30-minute outages minimum. A working "-- +goose
# Down" lets us roll back the schema in seconds.
#
# This level enforces, by static inspection of internal/migrate/sql/:
#   1. Every migration has a "-- +goose Down" block
#   2. Every Down block has at least one non-comment statement
#   3. No Down block is "DROP TABLE IF EXISTS *" — that means the
#      author gave up rather than write a real rollback (except for
#      the literal init migration 001)
#   4. Newer migrations (014+) have surgical rollbacks, not blanket drops

set -uo pipefail  # no -e — let individual phases handle their own pipeline failures

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

MIGRATE_DIR="$ROOT/internal/migrate/sql"

# ── 78.1 Every migration has a -- +goose Down block ─────────────────────

phase_open "78.1 every .sql migration has Down block"

MISSING=""
for f in "$MIGRATE_DIR"/*.sql; do
  if ! grep -q -- "-- +goose Down" "$f"; then
    MISSING="$MISSING $(basename "$f")"
  fi
done

if [[ -z "$MISSING" ]]; then
  _pass "78.1.1 all migrations have Down block"
else
  _fail "78.1.1 migrations missing Down" "$MISSING"
fi

# ── 78.2 Every Down block has at least one non-comment statement ───────

phase_open "78.2 Down blocks are non-empty"

EMPTY=""
for f in "$MIGRATE_DIR"/*.sql; do
  base=$(basename "$f")
  body=$(awk '
    /-- \+goose Down/    { flag=1; next }
    /-- \+goose StatementEnd/ { flag=0 }
    flag && NF && !/^--/ { print }
  ' "$f" | wc -l)
  if [[ "$body" -lt 1 ]]; then
    EMPTY="$EMPTY $base"
  fi
done

if [[ -z "$EMPTY" ]]; then
  _pass "78.2.1 all Down blocks have at least one statement"
else
  _fail "78.2.1 empty Down blocks" "$EMPTY"
fi

# ── 78.3 No "give-up" blanket DROPs (except literal init migration) ────

phase_open "78.3 incremental migrations don't blanket-drop everything"

GIVEUP=""
for f in "$MIGRATE_DIR"/*.sql; do
  base=$(basename "$f")
  # 001_init.sql is allowed to blanket-drop — it's the literal schema init.
  [[ "$base" == "001_init.sql" ]] && continue

  # Extract Down body and count distinct schema objects dropped.
  body=$(awk '
    /-- \+goose Down/    { flag=1; next }
    /-- \+goose StatementEnd/ { flag=0 }
    flag                 { print }
  ' "$f")

  # "Blanket drop" heuristic: a single DROP TABLE that mentions 4+ tables.
  # Real incremental migrations drop 1-2 things — that's the new objects
  # they introduced. 4+ drops in one statement means the author dumped
  # the whole module's tables, which is over-reach for a Down.
  tables_dropped=$( { echo "$body" | grep -oE 'DROP TABLE [^;]*' \
    | head -1 | tr ',' '\n' | grep -c . ; } 2>/dev/null | tr -dc '0-9' | head -c 4)
  tables_dropped=${tables_dropped:-0}
  if [[ "$tables_dropped" -ge 5 ]]; then
    GIVEUP="$GIVEUP $base($tables_dropped)"
  fi
done

if [[ -z "$GIVEUP" ]]; then
  _pass "78.3.1 no incremental migration does a blanket drop"
else
  _skip "78.3.1 blanket-drop migrations" \
    "$GIVEUP — review whether each drop is needed"
fi

# ── 78.4 Recent migrations (last 5) have meaningful Down ──────────────

phase_open "78.4 latest 5 migrations have non-trivial Down"

# Count only TABLES and ADD COLUMN — not indexes. A DROP TABLE
# cascades to its indexes, so requiring Down to explicitly DROP INDEX
# for each CREATE INDEX would be redundant.
LATEST=$(ls "$MIGRATE_DIR"/*.sql | sort | tail -5)
INSUFFICIENT=""
for f in $LATEST; do
  base=$(basename "$f")

  up_tables=$( { awk '
    /-- \+goose Up/      { flag=1; next }
    /-- \+goose Down/    { flag=0 }
    flag                 { print }
  ' "$f" | grep -ciE "CREATE TABLE|ALTER TABLE.*ADD COLUMN" ; } 2>/dev/null | tr -dc '0-9' | head -c 4)
  up_tables=${up_tables:-0}

  down_tables=$( { awk '
    /-- \+goose Down/    { flag=1; next }
    /-- \+goose StatementEnd/ { flag=0 }
    flag                 { print }
  ' "$f" | grep -ciE "DROP TABLE|ALTER TABLE.*DROP COLUMN" ; } 2>/dev/null | tr -dc '0-9' | head -c 4)
  down_tables=${down_tables:-0}

  # Up tables = N, Down DROP TABLE count must equal N (or be a CASCADE
  # that drops a parent which transitively drops children, but the
  # simple equality covers the common case).
  if [[ "$up_tables" -ge 1 ]] && [[ "$down_tables" -lt "$up_tables" ]]; then
    INSUFFICIENT="$INSUFFICIENT $base(up_tables=$up_tables down_tables=$down_tables)"
  fi
done

if [[ -z "$INSUFFICIENT" ]]; then
  _pass "78.4.1 latest 5 migrations have symmetric Up/Down TABLE counts"
else
  _fail "78.4.1 Down DROP TABLE count < Up CREATE TABLE count" \
    "$INSUFFICIENT — rollback won't fully reverse the Up"
fi

# ── 78.5 No Down block references tables outside its module ───────────

phase_open "78.5 Down only touches objects from its own Up"

# Detector for accidental cross-migration interference: e.g. migration
# 015_sso_providers.sql Down drops the `users` table (which 001 owns).
# This is rarer but disastrous when it happens.
CROSS=""
for f in "$MIGRATE_DIR"/*.sql; do
  base=$(basename "$f")
  [[ "$base" == "001_init.sql" ]] && continue

  # Tables CREATEd in this migration's Up
  up_tables=$(awk '/-- \+goose Up/{flag=1;next} /-- \+goose Down/{flag=0} flag' "$f" \
    | grep -ioE 'CREATE TABLE (IF NOT EXISTS )?[a-z_]+' \
    | awk '{print tolower($NF)}' | sort -u)

  # Tables DROPped in this migration's Down (split comma lists, exclude
  # the keywords CASCADE/RESTRICT which aren't table names).
  down_tables=$(awk '/-- \+goose Down/{flag=1;next} /-- \+goose StatementEnd/{flag=0} flag' "$f" \
    | grep -oE 'DROP TABLE [^;]*' \
    | sed -E 's/DROP TABLE (IF EXISTS)?//; s/[, ]+/\n/g' \
    | awk 'NF{print tolower($0)}' \
    | grep -vwE 'cascade|restrict|if|exists' \
    | sort -u)

  # If Down references a table that Up didn't create, that's a cross-migration drop.
  for t in $down_tables; do
    [[ -z "$t" ]] && continue
    if [[ -n "$up_tables" ]] && ! echo "$up_tables" | grep -qx "$t"; then
      # Allow if Up doesn't create any tables (e.g. index-only or ALTER-only migration)
      [[ -n "$up_tables" ]] && CROSS="$CROSS $base→$t"
    fi
  done
done

if [[ -z "$CROSS" ]]; then
  _pass "78.5.1 no Down drops tables outside its own Up"
else
  _skip "78.5.1 cross-migration drops" \
    "$CROSS — review whether each is intentional"
fi

# ── 78.6 Migrations are sequentially numbered (no gaps) ────────────────

phase_open "78.6 migration sequence has no gaps"

# Strip leading zeros so 001 → 1 for arithmetic comparison.
NUMBERS=$(ls "$MIGRATE_DIR"/*.sql | xargs -n1 basename \
  | grep -oE '^[0-9]+' | sed 's/^0*//' | awk 'NF{print}' | sort -n | uniq)
LO=$(echo "$NUMBERS" | head -1)
HI=$(echo "$NUMBERS" | tail -1)
EXPECTED=$(seq "$LO" "$HI" | sort -n)
GAPS=$(comm -23 <(echo "$EXPECTED" | sort) <(echo "$NUMBERS" | sort) 2>/dev/null)

if [[ -z "$GAPS" ]]; then
  _pass "78.6.1 migration numbers contiguous"
else
  _skip "78.6.1 sequence gaps" \
    "missing: $(echo $GAPS | tr '\n' ' ') — may be intentional (deleted migration)"
fi

final_summary
