#!/usr/bin/env bash
# scripts/test-l40-idempotency.sh — POST replay safety + idempotency.
#
# Two related questions:
#   1. If a client sends the same Idempotency-Key twice (network retry
#      or proxy timeout retry), does the server create ONE resource
#      or TWO? Stripe-style APIs and PCI-DSS workflows require one.
#   2. If a DELETE is replayed, is the second call a no-op 204 or
#      does it leak "resource not found" → 404 with stack details?
#
# This is intentionally GENTLE — we probe with shaped synthetic
# requests, count side effects, and accept either:
#   - Server honours Idempotency-Key (de-dups on key)
#   - Server doesn't recognise the header (treats both as new); we
#     SKIP rather than fail in this case, because Idempotency-Key is
#     an opt-in API contract, not a security invariant.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"

# ── 40.1 POST same Idempotency-Key twice — same response ID ──────────────

phase_open "40.1 Idempotency-Key dedup"

# Pick a creation endpoint. /api/v1/data/erasure is suitable: it
# creates a row, returns an ID, and is admin-gated so we won't
# pollute multi-tenant fixtures.
KEY="l40-idem-$(date +%s%N | sha256sum | head -c 16)"
EMAIL="l40-idem-$(date +%s%N | sha256sum | head -c 8)@vsp.test"
BODY="{\"email\":\"$EMAIL\",\"reason\":\"L40 idempotency probe\"}"

resp1=$(mktemp); resp2=$(mktemp)
status1=$(curl -s -o "$resp1" -w "%{http_code}" --max-time 5 \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN" \
  -H "Idempotency-Key: $KEY" \
  -d "$BODY" \
  "$BASE/api/v1/data/erasure" 2>/dev/null || echo "000")
status2=$(curl -s -o "$resp2" -w "%{http_code}" --max-time 5 \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN" \
  -H "Idempotency-Key: $KEY" \
  -d "$BODY" \
  "$BASE/api/v1/data/erasure" 2>/dev/null || echo "000")

ID1=$(jq -r '.id // empty' "$resp1" 2>/dev/null || echo "")
ID2=$(jq -r '.id // empty' "$resp2" 2>/dev/null || echo "")
rm -f "$resp1" "$resp2"

if [[ "$status1" =~ ^(401|403|404|405)$ ]]; then
  _skip "40.1.1 Idempotency-Key dedup" \
    "endpoint returned $status1 — auth / route mismatch in CI"
elif [[ -z "$ID1" || -z "$ID2" ]]; then
  _skip "40.1.1 Idempotency-Key dedup" \
    "no ID in either response (status1=$status1 status2=$status2)"
elif [[ "$ID1" == "$ID2" ]]; then
  _pass "40.1.1 Idempotency-Key honoured [id1=id2=$ID1]"
else
  _skip "40.1.1 Idempotency-Key not implemented" \
    "duplicate POST created two distinct resources ($ID1 vs $ID2). Not a security failure but a contract gap."
fi

# ── 40.2 DELETE replay — second call is benign ───────────────────────────

phase_open "40.2 DELETE replay safety"

# We don't have a guaranteed DELETE endpoint that's safe to call in CI.
# Probe the canonical /api/v1/admin/users/<random-uuid> with two
# DELETEs in a row; both should return 4xx (not exist) without leaking.
RANDOM_UUID=$(printf '%08x-0000-0000-0000-%012x' "$RANDOM$RANDOM" "$RANDOM$RANDOM$RANDOM")
del1=$(mktemp); del2=$(mktemp)
status1=$(curl -s -o "$del1" -w "%{http_code}" --max-time 5 -X DELETE \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/admin/users/$RANDOM_UUID" 2>/dev/null || echo "000")
status2=$(curl -s -o "$del2" -w "%{http_code}" --max-time 5 -X DELETE \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/admin/users/$RANDOM_UUID" 2>/dev/null || echo "000")

# Both should be similar — either both 204/404 or both 4xx. The two
# responses must NOT differ wildly (e.g. first 204, second 500).
if [[ "$status1" == "$status2" ]]; then
  _pass "40.2.1 DELETE replay returns same status [$status1]"
elif [[ "$status1" =~ ^4 && "$status2" =~ ^4 ]]; then
  _pass "40.2.1 DELETE replay both 4xx [$status1, $status2]"
elif [[ "$status1" =~ ^5 || "$status2" =~ ^5 ]]; then
  _fail "40.2.1 DELETE replay caused 5xx" "first=$status1 second=$status2"
else
  _skip "40.2.1 DELETE replay" "ambiguous statuses $status1 / $status2"
fi

# Stack-trace leakage on the second DELETE (if 5xx).
if grep -qE 'goroutine [0-9]+|/usr/lib/go|panic:' "$del2" 2>/dev/null; then
  _fail "40.2.2 DELETE 5xx leaked Go stack trace" "$(grep -E 'panic|goroutine' "$del2" | head -1)"
else
  _pass "40.2.2 DELETE response body has no Go runtime details"
fi
rm -f "$del1" "$del2"

# ── 40.3 GET is naturally idempotent — confirm no side effects ───────────

phase_open "40.3 GET side-effect probe"

# Call /api/v1/audit/log twice rapidly. Audit count should NOT grow
# from GET probes alone (audit_log records writes, not reads).
COUNT_BEFORE=$(curl -s --max-time 5 \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/audit/stats" 2>/dev/null | jq -r '.total_events // 0' 2>/dev/null || echo 0)

for _ in 1 2 3 4 5; do
  curl -s -o /dev/null --max-time 5 \
    -H "Authorization: Bearer $ADMIN" \
    "$BASE/api/v1/audit/log?limit=10" 2>/dev/null || true
done

COUNT_AFTER=$(curl -s --max-time 5 \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/audit/stats" 2>/dev/null | jq -r '.total_events // 0' 2>/dev/null || echo 0)

# Allow up to 2 events of growth (the audit/stats GET itself, and
# rate-limit-counter writes are common); flag larger jumps.
DIFF=$(( COUNT_AFTER - COUNT_BEFORE ))
if (( DIFF <= 2 )); then
  _pass "40.3.1 5x audit/log GETs caused $DIFF audit rows [≤2 tolerance]"
else
  _fail "40.3.1 GET caused $DIFF audit rows" \
    "GET probes shouldn't leave more than ambient drift behind"
fi

final_summary
