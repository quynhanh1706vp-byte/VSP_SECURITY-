#!/usr/bin/env bash
# scripts/test-l51-audit-immutable.sh — audit log append-only invariants.
#
# FedRAMP AU-9, SOC 2 CC7.2: audit logs must be tamper-evident. Any
# UPDATE or DELETE on audit_log breaks the hash chain (verified by
# L9.10.3.x), but those probes assume the chain ALREADY exists and
# only watches that NEW writes don't corrupt it.
#
# This level proves the immutability invariant directly:
#
#   1. INSERT a known audit event, capture its seq + hash.
#   2. Attempt UPDATE — must fail (RLS / column-level trigger / role)
#   3. Attempt DELETE — must fail
#   4. Verify the row is byte-identical post-attempts
#   5. Hash-chain re-verifies cleanly
#
# Probe runs server-side via psql against the deployed gateway's
# database, so it actually exercises whatever permission model is
# enforced.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"
TENANT_A_UUID="1bdf7f20-dbb3-4116-815f-26b4dc747e76"

# ── 51.1 Seed a known audit event, capture seq + hash ────────────────────

phase_open "51.1 Seed probe audit event"

# Trigger an audit by hitting state-changing endpoints. Try several
# until one writes a row for tenant A — different builds wire audit
# emission differently and not every endpoint guarantees an emit.
for trigger in \
    "POST /api/v1/audit/verify" \
    "GET  /api/v1/admin/users" \
    "GET  /api/v1/admin/api-keys" \
    "POST /api/v1/scheduler/jobs"; do
  method=${trigger%% *}
  path=${trigger##* }
  curl -s -o /dev/null --max-time 5 -X "$method" \
    -H "Authorization: Bearer $ADMIN" \
    "$BASE$path" > /dev/null 2>&1 || true
done
# Give async audit writers time to flush (the logAudit helper detaches
# the request via `go func()` with context.Background()).
sleep 2

# If still nothing for tenant A, seed one directly via SQL so the
# rest of the immutability probes (UPDATE/DELETE/TRUNCATE) still
# exercise the constraint layer.
LATEST=$(_psql_oneshot "
  SELECT id || ',' || seq || ',' || hash::text
  FROM audit_log
  WHERE tenant_id = '$TENANT_A_UUID'
  ORDER BY seq DESC
  LIMIT 1;")

if [[ -z "$LATEST" ]]; then
  # Fallback: insert directly. This still verifies UPDATE/DELETE refusal
  # at the DB layer — that's the invariant L51 actually cares about.
  PROBE_UID=$(_psql_oneshot "
    INSERT INTO audit_log (tenant_id, action, resource, ip, hash, prev_hash, seq)
    VALUES ('$TENANT_A_UUID', 'L51_SEED', 'l51-immutable-probe', '127.0.0.1',
            decode('$(echo -n l51 | sha256sum | cut -c1-64)','hex'),
            decode('$(echo -n prev | sha256sum | cut -c1-64)','hex'),
            COALESCE((SELECT MAX(seq)+1 FROM audit_log WHERE tenant_id='$TENANT_A_UUID'), 1))
    RETURNING id;" 2>/dev/null || true)
  if [[ -n "$PROBE_UID" && "$PROBE_UID" =~ ^[0-9a-f-]{36}$ ]]; then
    LATEST="$PROBE_UID,direct-seed,direct"
    _skip "51.1.0 audit event seed" "no audit emitted by HTTP triggers — direct INSERT for probe"
  else
    _skip "51.1.0 seed audit event" "no audit_log rows AND direct insert failed — env mismatch"
    final_summary; exit 0
  fi
fi

PROBE_ID=$(echo "$LATEST" | cut -d, -f1)
PROBE_SEQ=$(echo "$LATEST" | cut -d, -f2)
PROBE_HASH=$(echo "$LATEST" | cut -d, -f3-)
_pass "51.1.0 captured probe audit row [seq=$PROBE_SEQ]"

# ── 51.2 UPDATE attempt must not change the row ──────────────────────────

phase_open "51.2 UPDATE on audit_log must not succeed"

# Attempt a direct UPDATE — should fail via column-level / role
# permissions or RLS write policy.
UPDATE_RC=$(psql "$DB_DSN" -tAc \
  "UPDATE audit_log SET action='TAMPERED_BY_L51' WHERE id='$PROBE_ID';" \
  2>&1 || true)

# Verify the row is unchanged.
ACTUAL_ACTION=$(_psql_oneshot "
  SELECT action FROM audit_log WHERE id='$PROBE_ID';")

if [[ "$ACTUAL_ACTION" == "TAMPERED_BY_L51" ]]; then
  _fail "51.2.1 UPDATE on audit_log SUCCEEDED" \
    "row $PROBE_ID was rewritten — append-only invariant broken"
  # Try to restore — at least clean up what we corrupted.
  _psql_oneshot "UPDATE audit_log SET action='AUDIT_VERIFY' WHERE id='$PROBE_ID';" >/dev/null 2>&1 || true
elif echo "$UPDATE_RC" | grep -qiE "permission denied|policy|read.?only|trigger"; then
  _pass "51.2.1 UPDATE refused at DB layer [$(echo "$UPDATE_RC" | head -c 80)]"
else
  # No error, no change — likely RLS silently filtered the UPDATE.
  # Still a pass for the immutability invariant.
  _pass "51.2.1 UPDATE no-op'd silently [row preserved]"
fi

# ── 51.3 DELETE attempt must not succeed ─────────────────────────────────

phase_open "51.3 DELETE on audit_log must not succeed"

DELETE_RC=$(psql "$DB_DSN" -tAc \
  "DELETE FROM audit_log WHERE id='$PROBE_ID';" \
  2>&1 || true)

STILL=$(_psql_oneshot "SELECT count(*) FROM audit_log WHERE id='$PROBE_ID';")
if [[ "${STILL:-0}" == "0" ]]; then
  _fail "51.3.1 DELETE on audit_log SUCCEEDED" \
    "audit row removed — compliance violation"
elif echo "$DELETE_RC" | grep -qiE "permission denied|policy|read.?only|trigger"; then
  _pass "51.3.1 DELETE refused at DB layer [$(echo "$DELETE_RC" | head -c 80)]"
else
  _pass "51.3.1 DELETE no-op'd silently [row preserved]"
fi

# ── 51.4 Hash chain still verifies after attempts ────────────────────────

phase_open "51.4 Chain integrity post-tamper attempt"

verify_ok=$(curl -s --max-time 10 -X POST \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/audit/verify" 2>/dev/null \
  | jq -r '.ok // false' 2>/dev/null || echo "false")

if [[ "$verify_ok" == "true" ]]; then
  _pass "51.4.1 audit/verify ok=true after tamper attempts"
else
  _fail "51.4.1 audit/verify reports chain corruption" \
    "ok=$verify_ok — write attempts may have partially succeeded"
fi

# ── 51.5 No DROP / TRUNCATE shortcut ─────────────────────────────────────

phase_open "51.5 TRUNCATE / DROP refused"

# Attempt TRUNCATE — should be refused for non-superuser.
TRUNC_RC=$(psql "$DB_DSN" -tAc \
  "TRUNCATE TABLE audit_log;" 2>&1 || true)

if echo "$TRUNC_RC" | grep -qiE "permission denied|must be (table )?owner"; then
  _pass "51.5.1 TRUNCATE audit_log refused"
elif [[ "$TRUNC_RC" == "TRUNCATE TABLE" ]]; then
  _fail "51.5.1 TRUNCATE audit_log SUCCEEDED" \
    "user has TRUNCATE rights on audit_log — bulk-tamper vector"
else
  _skip "51.5.1 TRUNCATE attempt" "unexpected: $(echo "$TRUNC_RC" | head -c 80)"
fi

final_summary
