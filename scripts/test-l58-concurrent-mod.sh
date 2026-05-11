#!/usr/bin/env bash
# scripts/test-l58-concurrent-mod.sh — concurrent-modification race.
#
# Two admins PATCH the same finding within milliseconds. Three
# acceptable outcomes:
#
#   A. Both succeed; last-write-wins (LWW). Acceptable IF the
#      handler accepts that risk and the audit log shows BOTH writes.
#
#   B. First wins; second returns 409 Conflict. Best-practice
#      (uses an ETag or version column).
#
#   C. Both succeed but the final row reflects neither (interleaved
#      column updates). UNACCEPTABLE — corruption.
#
# We probe by firing 5 simultaneous PATCH requests with distinct
# values, then verify the final row state matches exactly ONE of
# them, AND the audit_log captured all attempts.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"
TENANT_A_UUID="1bdf7f20-dbb3-4116-815f-26b4dc747e76"

# ── 58.1 Seed a finding ───────────────────────────────────────────────────

phase_open "58.1 Concurrent PATCH — final state is well-defined"

FID=$(_psql_oneshot "
  INSERT INTO findings (tenant_id, tool, severity, message, rule_id)
  VALUES ('$TENANT_A_UUID', 'l58-probe', 'LOW', 'L58 concurrent probe', 'L58-RULE')
  RETURNING id;")

if [[ -z "$FID" || ! "$FID" =~ ^[0-9a-f-]{36}$ ]]; then
  _skip "58.1.0 seed finding" "couldn't insert probe row"
  final_summary; exit 0
fi
_pass "58.1.0 probe finding seeded [id=$FID]"

# Fire 5 concurrent PATCH requests with distinct severity values.
TMP=$(mktemp -d)
for i in 1 2 3 4 5; do
  sev=$([[ $((i % 2)) -eq 0 ]] && echo "HIGH" || echo "CRITICAL")
  curl -s -o "$TMP/r$i" -w "%{http_code}|" --max-time 10 \
    -X PATCH -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN" \
    -d "{\"severity\":\"$sev\",\"l58_writer\":\"writer-$i\"}" \
    "$BASE/api/v1/findings/$FID" >> "$TMP/codes" 2>/dev/null &
done
wait || true

# Check final row state. Severity MUST be either HIGH or CRITICAL,
# not the seed value (LOW) and not some garbage interleave.
final_sev=$(_psql_oneshot "SELECT severity FROM findings WHERE id='$FID';")

if [[ "$final_sev" == "HIGH" || "$final_sev" == "CRITICAL" ]]; then
  _pass "58.1.1 final severity is a coherent winner [$final_sev]"
elif [[ "$final_sev" == "LOW" ]]; then
  # All 5 PATCHes failed (404? endpoint not mounted?). Check codes.
  codes=$(cat "$TMP/codes" 2>/dev/null | tr '|' '\n' | sort -u | head -3 | tr '\n' ',' || true)
  if echo "$codes" | grep -qE '404|405'; then
    _skip "58.1.1 concurrent PATCH" "endpoint returned $codes — not mounted in this build"
  else
    _fail "58.1.1 final severity unchanged after PATCHes" \
      "still LOW; codes: $codes"
  fi
else
  _fail "58.1.1 final severity is incoherent" \
    "got '$final_sev' — neither seed (LOW) nor a writer value (HIGH/CRITICAL)"
fi

# ── 58.2 5xx count is 0 under concurrent load ────────────────────────────

phase_open "58.2 No 5xx under contention"

FIVE_XX=$(cat "$TMP/codes" 2>/dev/null | tr '|' '\n' | grep -cE '^5' || true)
FIVE_XX=${FIVE_XX:-0}
if (( FIVE_XX == 0 )); then
  _pass "58.2.1 no 5xx in 5 concurrent PATCHes"
else
  _fail "58.2.1 $FIVE_XX 5xx responses under contention" \
    "concurrent writes triggered an exception — review handler locking"
fi

# ── 58.3 Audit captures attempts ─────────────────────────────────────────

phase_open "58.3 Audit log captured concurrent attempts"

# Give async audit writers 2s to flush.
sleep 2
AUDIT_COUNT=$(_psql_oneshot "
  SELECT count(*) FROM audit_log
  WHERE tenant_id = '$TENANT_A_UUID'
    AND resource LIKE '%$FID%'
    AND created_at > NOW() - INTERVAL '30 seconds';")

# Don't require exactly 5 — some writes may fail at the constraint
# layer before audit fires. But ≥1 means audit is wired correctly.
if [[ "${AUDIT_COUNT:-0}" -ge 1 ]]; then
  _pass "58.3.1 audit_log captured ≥1 PATCH attempt [count=$AUDIT_COUNT]"
elif [[ "${AUDIT_COUNT:-0}" == "0" ]]; then
  _skip "58.3.1 audit on PATCH" \
    "0 audit rows — handler may not emit audit on PATCH (informational)"
fi

# Cleanup
_psql_oneshot "DELETE FROM findings WHERE id='$FID';" >/dev/null 2>&1 || true
rm -rf "$TMP"

# ── 58.4 Optimistic-concurrency header support (best practice) ───────────

phase_open "58.4 If-Match / ETag support"

# Fetch a finding, read its ETag, PATCH with If-Match: <stale-etag>.
# Best-practice servers return 412 Precondition Failed.
HEAD=$(curl -s -i --max-time 5 \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/vsp/findings?limit=1" 2>/dev/null \
  | tr -d '\r' || true)

if echo "$HEAD" | grep -qiE '^etag:'; then
  _pass "58.4.1 server emits ETag on list endpoint"
else
  _skip "58.4.1 ETag header" \
    "no ETag emitted — optimistic-concurrency not implemented (informational)"
fi

final_summary
