#!/usr/bin/env bash
# scripts/start-scheduler-api.sh
# ─────────────────────────────────────────────────────────────────────
# Launcher for vsp-scheduler (port 8092).
# setsid + nohup + disown pattern.
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

BIN="${VSP_SCHED_BIN:-./vsp-scheduler}"
ADDR="${VSP_SCHED_ADDR:-:8092}"
STORE="${VSP_SCHED_STORE:-/var/lib/vsp/scheduler.json}"
RUNS="${VSP_SCHED_RUNS:-/var/lib/vsp/scheduler-runs.json}"
LOG="${VSP_SCHED_LOG:-/var/log/vsp/scheduler.log}"
PIDF="${VSP_SCHED_PID:-/var/run/vsp/scheduler.pid}"

LOG_DIR="$(dirname "$LOG")"; PID_DIR="$(dirname "$PIDF")"
[[ -w "$LOG_DIR" ]] || { LOG_DIR=/tmp/vsp-runtime; mkdir -p "$LOG_DIR"; LOG="$LOG_DIR/scheduler.log"; }
[[ -w "$PID_DIR" ]] || { PID_DIR=/tmp/vsp-runtime; mkdir -p "$PID_DIR"; PIDF="$PID_DIR/scheduler.pid"; }

is_running() {
  [[ -f "$PIDF" ]] || return 1
  local pid; pid=$(<"$PIDF")
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

cmd_check() {
  local errs=0
  echo "→ Pre-flight"
  if [[ -x "$BIN" ]]; then
    echo "  ✓ binary $BIN"
  else
    echo "  ✗ binary $BIN missing — run: go build -o vsp-scheduler ./cmd/scheduler-api"
    errs=$((errs+1))
  fi

  local sdir; sdir=$(dirname "$STORE")
  if [[ -w "$sdir" ]]; then
    echo "  ✓ store dir $sdir writable"
  else
    echo "  ⚠ store dir $sdir not writable"
    errs=$((errs+1))
  fi

  local port="${ADDR#:}"
  if command -v ss >/dev/null && ss -ltn 2>/dev/null | grep -qE ":${port}\s"; then
    echo "  ⚠ port $port in use:"; ss -ltnp 2>/dev/null | grep -E ":${port}\s" | sed 's/^/      /'
  else
    echo "  ✓ port $port free"
  fi

  # Check upstream services exist (warn only)
  for upstream in "trivy-api:8090" "cosign-api:8091" "sw-inventory:8094"; do
    name="${upstream%:*}"; up_port="${upstream##*:}"
    if curl -sf --max-time 2 "http://127.0.0.1:${up_port}/healthz" >/dev/null 2>&1; then
      echo "  ✓ upstream $name healthy"
    else
      echo "  ⚠ upstream $name NOT reachable on :$up_port — jobs targeting it will fail"
    fi
  done

  if (( errs > 0 )); then echo; echo "✗ $errs check(s) failed"; return 1; fi
  return 0
}

cmd_start() {
  if is_running; then echo "✓ already running (pid=$(<"$PIDF"))"; return 0; fi
  cmd_check || exit 2

  echo "→ starting on $ADDR  log=$LOG"
  setsid nohup "$BIN" \
      -addr "$ADDR" \
      -store "$STORE" \
      -runs "$RUNS" \
      >>"$LOG" 2>&1 &
  local pid=$!
  disown "$pid" 2>/dev/null || true
  echo "$pid" > "$PIDF"

  local i port="${ADDR#:}"
  for i in 1 2 3 4 5 6; do
    sleep 0.5
    if curl -sf "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      echo "✓ vsp-scheduler up (pid=$pid)"
      curl -s "http://127.0.0.1:${port}/healthz"; echo
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "✗ died — log tail:"; tail -20 "$LOG" | sed 's/^/    /'
      rm -f "$PIDF"; exit 1
    fi
  done
  echo "⚠ pid=$pid running but /healthz not responding"
  tail -10 "$LOG" | sed 's/^/    /'
}

cmd_stop() {
  if ! is_running; then echo "· not running"; rm -f "$PIDF"; return 0; fi
  local pid; pid=$(<"$PIDF")
  echo "→ stopping pid=$pid"
  kill -TERM "$pid" 2>/dev/null || true
  for i in 1 2 3 4 5 6; do
    sleep 0.5
    kill -0 "$pid" 2>/dev/null || { echo "✓ stopped"; rm -f "$PIDF"; return 0; }
  done
  kill -KILL "$pid" 2>/dev/null || true
  rm -f "$PIDF"
}

cmd_status() {
  local port="${ADDR#:}"
  if is_running; then
    echo "✓ running (pid=$(<"$PIDF"))"
    curl -s "http://127.0.0.1:${port}/healthz" || echo "  /healthz not responding"
    echo
  else echo "✗ not running"; exit 1; fi
}
cmd_tail() { tail -F "$LOG"; }

case "${1:-start}" in
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  restart) cmd_stop; sleep 0.5; cmd_start ;;
  status)  cmd_status ;;
  tail)    cmd_tail ;;
  check)   cmd_check ;;
  *) echo "usage: $0 {start|stop|restart|status|tail|check}"; exit 2 ;;
esac
