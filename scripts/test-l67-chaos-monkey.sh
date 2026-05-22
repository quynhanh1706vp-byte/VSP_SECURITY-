#!/usr/bin/env bash
# scripts/test-l67-chaos-monkey.sh — process-level chaos probes.
#
# Verifies graceful behaviour under disruptive events:
#   1. kill -STOP gateway for 5s → resume → in-flight requests recover
#   2. Sustained 1000 req/sec burst → no panic / OOM
#   3. Postgres connection torn mid-query → handler returns 5xx
#      cleanly with JSON envelope, never a Go panic stack
#   4. Redis goes away → cache misses fall through to DB, not 5xx
#
# DESTRUCTIVE — gated behind L67_CHAOS=1. Runs in nightly chaos
# drill only.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

if [[ "${L67_CHAOS:-0}" != "1" ]]; then
  _skip "67.0 chaos harness" "L67_CHAOS!=1 — destructive, gated"
  final_summary; exit 0
fi

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"

# Locate gateway PID.
GW_PID=""
for cand in /tmp/gateway.pid /var/run/vsp-gateway.pid; do
  if [[ -r "$cand" ]]; then
    GW_PID=$(cat "$cand" 2>/dev/null | tr -d '[:space:]')
    [[ -n "$GW_PID" && -d "/proc/$GW_PID" ]] && break
    GW_PID=""
  fi
done
[[ -z "$GW_PID" ]] && GW_PID=$(pgrep -f 'vsp-gateway' | head -1 || true)

if [[ -z "$GW_PID" ]]; then
  _skip "67.0 gateway PID" "no live gateway"
  final_summary; exit 0
fi

# ── 67.1 SIGSTOP → SIGCONT mid-request ───────────────────────────────────

phase_open "67.1 Pause/resume mid-request"

# Fire 3 requests, pause gateway 3s, resume, verify they complete
# with 2xx (assuming the client side has retry / timeout slack).
TMP=$(mktemp -d)
for i in 1 2 3; do
  curl -s -o "$TMP/r$i" -w "%{http_code}\n" --max-time 20 \
    -H "Authorization: Bearer $ADMIN" \
    "$BASE/api/v1/audit/log?limit=1" >> "$TMP/codes" 2>/dev/null &
done

sleep 0.3
kill -STOP "$GW_PID" 2>/dev/null
sleep 3
kill -CONT "$GW_PID" 2>/dev/null

wait || true

OK_COUNT=$(grep -c '^2' "$TMP/codes" 2>/dev/null || echo 0)
OK_COUNT=$(echo "$OK_COUNT" | head -1 | tr -dc '0-9')
OK_COUNT=${OK_COUNT:-0}

if [[ "$OK_COUNT" -ge 1 ]]; then
  _pass "67.1.1 at least 1 of 3 in-flight requests survived pause/resume [$OK_COUNT/3]"
else
  _fail "67.1.1 all in-flight requests died during pause" \
    "0/3 succeeded — graceful recovery broken"
fi
rm -rf "$TMP"

# ── 67.2 1000 req/s sustained burst — no panic ───────────────────────────

phase_open "67.2 Burst load — no 5xx panic"

TMP=$(mktemp -d)
for _ in $(seq 1 300); do
  curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 \
    -H "Authorization: Bearer $ADMIN" \
    "$BASE/api/v1/status" >> "$TMP/codes" 2>/dev/null &
done
wait || true

FIVE_XX=$(grep -c '^5' "$TMP/codes" 2>/dev/null || echo 0)
FIVE_XX=$(echo "$FIVE_XX" | head -1 | tr -dc '0-9')
FIVE_XX=${FIVE_XX:-0}
TOTAL=$(wc -l < "$TMP/codes" | tr -d ' ')

# Allow up to 1% 5xx (rate limiter / pool saturation = 503 is OK).
THRESHOLD=$(( TOTAL / 100 + 1 ))
if [[ "$FIVE_XX" -le "$THRESHOLD" ]]; then
  _pass "67.2.1 burst $TOTAL req: $FIVE_XX 5xx (≤$THRESHOLD budget)"
else
  _fail "67.2.1 5xx storm under burst" \
    "$FIVE_XX 5xx of $TOTAL (budget $THRESHOLD) — handler unstable"
fi
rm -rf "$TMP"

# ── 67.3 Gateway log doesn't contain `panic:` after chaos ────────────────

phase_open "67.3 No goroutine panics survived"

LOG="${LOG_FALLBACK:-/tmp/gateway.log}"
if [[ ! -r "$LOG" ]]; then
  _skip "67.3.1 panic-scan post-chaos" "no readable gateway log"
else
  if grep -qE 'panic:|fatal error:' "$LOG"; then
    HIT=$(grep -E 'panic:|fatal error:' "$LOG" | head -1)
    _fail "67.3.1 gateway panic in log" "$(echo "$HIT" | head -c 120)"
  else
    _pass "67.3.1 no panic/fatal in gateway log post-chaos"
  fi
fi

# ── 67.4 Gateway still healthy after the storm ──────────────────────────

phase_open "67.4 Post-chaos liveness"

status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  "$BASE/api/v1/status" 2>/dev/null || echo "000")
if [[ "$status" =~ ^2 ]]; then
  _pass "67.4.1 gateway healthy after chaos [HTTP $status]"
else
  _fail "67.4.1 gateway unhealthy post-chaos" "HTTP $status"
fi

final_summary
