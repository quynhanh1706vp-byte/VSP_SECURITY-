#!/usr/bin/env bash
# scripts/test-l14-perf.sh — perf smoke + soft regression gate.
#
# 30-second sustained burst @ configurable RPS against the cached and
# uncached read endpoints, then asserts P99 latency stays under a soft
# baseline. Watches goroutine count and RSS before/after to flag
# obvious leaks. NOT a full soak (those need >5 min); this is a CI-
# affordable smoke.
#
# Pre-flight: $JWT_SECRET, gateway running, vegeta installed.
#
# Tunables via env:
#   PERF_RPS   (default 50)   target RPS
#   PERF_DUR   (default 30s)  vegeta duration
#   PERF_P99_MS (default 500) P99 ceiling (ms)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command vegeta jq curl

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

NOW=$(date +%s); EXP=$((NOW + 3600))
H=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
P=$(printf '{"sub":"l14@vsp.local","email":"l14@vsp.local","role":"admin","tenant_id":"default","iat":%d,"exp":%d}' \
  "$NOW" "$EXP" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
S=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
  | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
ADMIN="$H.$P.$S"

PERF_RPS="${PERF_RPS:-50}"
PERF_DUR="${PERF_DUR:-30s}"
PERF_P99_MS="${PERF_P99_MS:-500}"

# ── 12.1 Baseline RSS + goroutine count ────────────────────────────────────

phase_open "12.1 Pre-burst baseline"

GW_PID=$(pgrep -f "/usr/local/bin/vsp-gateway" | head -1)
if [[ -z "$GW_PID" ]]; then
  _skip "12.1 baseline" "gateway pid not found"
  final_summary; exit $?
fi

RSS_BEFORE=$(awk '/VmRSS/ {print $2}' "/proc/$GW_PID/status" 2>/dev/null)
GOROUTINES_BEFORE=$(curl -s --max-time 5 "$BASE/debug/pprof/goroutine?debug=1" 2>/dev/null | head -1 | grep -oE 'total [0-9]+' | grep -oE '[0-9]+')
GOROUTINES_BEFORE=${GOROUTINES_BEFORE:-0}
_pass "12.1.1 baseline captured [RSS=${RSS_BEFORE}KiB, goroutines=$GOROUTINES_BEFORE]"

# ── 12.2 Sustained burst against cached endpoint ───────────────────────────

phase_open "12.2 Sustained @ ${PERF_RPS} RPS for ${PERF_DUR}"

# 50 RPS × 30s = 1500 requests. Hits the cached findings/summary
# endpoint so we exercise the hot path that L4-B caught the cross-
# tenant leak in.
TARGETS=$(mktemp)
RESULTS=$(mktemp)
{
  echo "GET $BASE/api/v1/vsp/findings/summary"
  echo "Authorization: Bearer $ADMIN"
  echo
  echo "GET $BASE/api/v1/audit/stats"
  echo "Authorization: Bearer $ADMIN"
  echo
  echo "GET $BASE/api/v1/kpi/sanity"
  echo "Authorization: Bearer $ADMIN"
  echo
} > "$TARGETS"

vegeta attack -rate="$PERF_RPS" -duration="$PERF_DUR" -targets="$TARGETS" 2>/dev/null \
  | vegeta encode > "$RESULTS"

REPORT=$(vegeta report -type=json < "$RESULTS")
SUCCESS_RATE=$(echo "$REPORT" | jq -r '.success * 100')
P50=$(echo "$REPORT" | jq -r '.latencies.["50th"] / 1000000')   # ns → ms
P95=$(echo "$REPORT" | jq -r '.latencies.["95th"] / 1000000')
P99=$(echo "$REPORT" | jq -r '.latencies.["99th"] / 1000000')
RPS_OBS=$(echo "$REPORT" | jq -r '.rate')
TOTAL=$(echo "$REPORT" | jq -r '.requests')

rm -f "$TARGETS" "$RESULTS"

_pass "12.2.1 burst issued [$TOTAL requests, ${RPS_OBS%.*} obs RPS]"

# Success rate should be ≥ 99% (cache miss + DB hit can produce
# transient 5xx but should be vanishingly rare at this load).
SR_INT=${SUCCESS_RATE%.*}
if (( SR_INT >= 99 )); then
  _pass "12.2.2 success rate ≥ 99% [${SUCCESS_RATE}%]"
else
  _fail "12.2.2 success rate" "${SUCCESS_RATE}% (need ≥99%)"
fi

# Latency gate.
P99_INT=${P99%.*}
if (( P99_INT <= PERF_P99_MS )); then
  _pass "12.2.3 P99 ≤ ${PERF_P99_MS}ms [${P99}ms, P50=${P50}ms, P95=${P95}ms]"
else
  _fail "12.2.3 P99 over budget" "${P99}ms exceeds ${PERF_P99_MS}ms ceiling"
fi

# ── 12.3 Post-burst leak indicators ────────────────────────────────────────

phase_open "12.3 Post-burst — RSS + goroutine drift"

sleep 3   # let any in-flight goroutines wind down
RSS_AFTER=$(awk '/VmRSS/ {print $2}' "/proc/$GW_PID/status" 2>/dev/null)
GOROUTINES_AFTER=$(curl -s --max-time 5 "$BASE/debug/pprof/goroutine?debug=1" 2>/dev/null | head -1 | grep -oE 'total [0-9]+' | grep -oE '[0-9]+')
GOROUTINES_AFTER=${GOROUTINES_AFTER:-0}

# Allow ≤ 30% RSS growth and ≤ 50 goroutine net-add. These thresholds
# are deliberately loose for a 30s smoke; a real soak would use tighter
# bounds. Tighten when leaks are observed.
RSS_DELTA=$(( RSS_AFTER - RSS_BEFORE ))
RSS_PCT=$(( RSS_DELTA * 100 / (RSS_BEFORE + 1) ))
GR_DELTA=$(( GOROUTINES_AFTER - GOROUTINES_BEFORE ))

if (( RSS_PCT <= 30 )); then
  _pass "12.3.1 RSS drift ≤ 30% [${RSS_BEFORE}→${RSS_AFTER}KiB, +${RSS_DELTA}KiB / ${RSS_PCT}%]"
else
  _fail "12.3.1 RSS jumped" "${RSS_PCT}% growth (${RSS_BEFORE}→${RSS_AFTER}KiB)"
fi

if (( GR_DELTA <= 50 )); then
  _pass "12.3.2 goroutine drift ≤ 50 [${GOROUTINES_BEFORE}→${GOROUTINES_AFTER}, +${GR_DELTA}]"
else
  _fail "12.3.2 goroutine leak" "${GR_DELTA} extra goroutines after burst"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
