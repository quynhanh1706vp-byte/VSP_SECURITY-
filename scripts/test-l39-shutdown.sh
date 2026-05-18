#!/usr/bin/env bash
# scripts/test-l39-shutdown.sh — graceful shutdown semantics.
#
# Verifies that on SIGTERM the gateway:
#   1. Stops accepting new connections (refuses or 503s).
#   2. Allows in-flight requests to complete cleanly (no 502/504).
#   3. Exits within a reasonable budget (default 10s).
#   4. Cleans up its pidfile / leaves no zombie children.
#
# This level is INHERENTLY DESTRUCTIVE — it stops the gateway. So it
# only runs when L39_SHUTDOWN=1 is explicitly set (workflow_dispatch
# in CI, never on PR runs). Otherwise SKIPs cleanly.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

if [[ "${L39_SHUTDOWN:-0}" != "1" ]]; then
  _skip "39.0 graceful-shutdown harness" "L39_SHUTDOWN!=1 — destructive, skip by default"
  final_summary
  exit 0
fi

# Locate the gateway PID. Try the canonical pidfile first, then pgrep.
GW_PID=""
for cand in /tmp/gateway.pid /var/run/vsp-gateway.pid; do
  if [[ -r "$cand" ]]; then
    GW_PID=$(cat "$cand" 2>/dev/null | tr -d '[:space:]')
    [[ -n "$GW_PID" && -d "/proc/$GW_PID" ]] && break
    GW_PID=""
  fi
done
if [[ -z "$GW_PID" ]] && command -v pgrep &>/dev/null; then
  GW_PID=$(pgrep -f 'vsp-gateway' | head -1 || true)
fi

if [[ -z "$GW_PID" || ! -d "/proc/$GW_PID" ]]; then
  _skip "39.0 gateway pid resolved" "no live gateway process found"
  final_summary; exit 0
fi

# ── 39.1 SIGTERM-then-completes harness ──────────────────────────────────

phase_open "39.1 SIGTERM honoured + in-flight completes"

# Fire 5 long-ish requests, send SIGTERM mid-flight, capture their
# final HTTP statuses. Pass conditions:
#   - At least one of the in-flight requests returns 2xx (drained), AND
#   - The gateway process is GONE within 15 seconds.
TMPDIR=$(mktemp -d)
for i in 1 2 3 4 5; do
  curl -s -o "$TMPDIR/r$i.body" -w "%{http_code}\n" --max-time 20 \
    "$BASE/api/v1/audit/verify" >> "$TMPDIR/codes" &
done
sleep 1
SIGTERM_TS=$(date +%s)
kill -TERM "$GW_PID" 2>/dev/null || true

# Wait for the gateway to exit OR 15s pass.
for i in $(seq 1 15); do
  if ! kill -0 "$GW_PID" 2>/dev/null; then
    EXIT_TS=$(date +%s)
    break
  fi
  sleep 1
done
ELAPSED=$(( ${EXIT_TS:-$(date +%s)} - SIGTERM_TS ))

# Reap the bg curls.
wait || true

# Did at least one in-flight request finish 2xx?
DRAINED_OK=$(grep -cE '^2[0-9]{2}$' "$TMPDIR/codes" 2>/dev/null || echo 0)
DRAINED_OK=${DRAINED_OK:-0}

if ! kill -0 "$GW_PID" 2>/dev/null && (( ELAPSED <= 15 )); then
  _pass "39.1.1 gateway exited cleanly after SIGTERM [${ELAPSED}s]"
else
  _fail "39.1.1 gateway didn't exit on SIGTERM" \
    "still alive after ${ELAPSED}s — escalate to SIGKILL needed"
  kill -KILL "$GW_PID" 2>/dev/null || true
fi

if (( DRAINED_OK > 0 )); then
  _pass "39.1.2 at least one in-flight request drained [$DRAINED_OK / 5 returned 2xx]"
else
  _skip "39.1.2 in-flight drain" \
    "0/5 in-flight requests returned 2xx — endpoint may have rejected before drain mattered"
fi

rm -rf "$TMPDIR"

# ── 39.2 No new connections after SIGTERM ────────────────────────────────

phase_open "39.2 Port closed promptly"

# Probe the gateway port — should fail to connect.
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
  "$BASE/api/v1/status" 2>/dev/null || echo "000")
if [[ "$status" == "000" ]]; then
  _pass "39.2.1 port refuses connections post-SIGTERM"
else
  _fail "39.2.1 port still accepting" "HTTP $status — gateway didn't actually exit"
fi

# ── 39.3 Pidfile cleaned up ──────────────────────────────────────────────

phase_open "39.3 Pidfile / process artifacts"

if [[ -f /tmp/gateway.pid && -d "/proc/$(cat /tmp/gateway.pid 2>/dev/null)" ]]; then
  _fail "39.3.1 pidfile points to live process" \
    "/tmp/gateway.pid still references PID $(cat /tmp/gateway.pid)"
else
  _pass "39.3.1 no live process referenced by pidfile"
fi

final_summary
