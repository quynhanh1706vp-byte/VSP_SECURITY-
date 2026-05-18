#!/usr/bin/env bash
# scripts/start-sw-inventory.sh
# ─────────────────────────────────────────────────────────────────────
# Launcher for vsp-sw-inventory (port 8094)
# Mirror of start-cosign-api.sh, with same setsid+nohup+disown pattern.
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

BIN="${VSP_SWI_BIN:-./vsp-sw-inventory}"
ADDR="${VSP_SWI_ADDR:-:8094}"
STORE="${VSP_SWI_STORE:-/var/lib/vsp/sw-inventory.json}"
KEY="${VSP_SWI_KEY:-/etc/vsp/sw-agent.key}"
LOG_DIR="$(dirname "${VSP_SWI_LOG:-/var/log/vsp/sw-inventory.log}")"
PID_DIR="$(dirname "${VSP_SWI_PID:-/var/run/vsp/sw-inventory.pid}")"
LOG="${VSP_SWI_LOG:-/var/log/vsp/sw-inventory.log}"
PIDF="${VSP_SWI_PID:-/var/run/vsp/sw-inventory.pid}"

# fallback runtime
[[ -w "$LOG_DIR" ]] || { LOG_DIR=/tmp/vsp-runtime; mkdir -p "$LOG_DIR"; LOG="$LOG_DIR/sw-inventory.log"; }
[[ -w "$PID_DIR" ]] || { PID_DIR=/tmp/vsp-runtime; mkdir -p "$PID_DIR"; PIDF="$PID_DIR/sw-inventory.pid"; }

is_running() {
  [[ -f "$PIDF" ]] || return 1
  local pid; pid=$(<"$PIDF")
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

cmd_start() {
  if is_running; then echo "✓ already running (pid=$(<"$PIDF"))"; return 0; fi

  echo "→ Pre-flight"
  if [[ ! -x "$BIN" ]]; then
    echo "  ✗ binary $BIN not found — run: go build -o vsp-sw-inventory ./cmd/sw-inventory"
    exit 2
  fi
  echo "  ✓ binary $BIN"
  echo "  ✓ store=$STORE  key=$KEY  log=$LOG"

  echo "→ starting on $ADDR"
  setsid nohup "$BIN" \
      -addr "$ADDR" \
      -store "$STORE" \
      -agent-key-file "$KEY" \
      >>"$LOG" 2>&1 &
  local pid=$!
  disown "$pid" 2>/dev/null || true
  echo "$pid" > "$PIDF"

  local i port="${ADDR#:}"
  for i in 1 2 3 4 5 6; do
    sleep 0.5
    if curl -sf "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      echo "✓ vsp-sw-inventory up (pid=$pid)"
      curl -s "http://127.0.0.1:${port}/healthz"
      echo
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "✗ died during startup — log tail:"
      tail -20 "$LOG" | sed 's/^/    /'
      rm -f "$PIDF"
      exit 1
    fi
  done
  echo "⚠ pid=$pid running but /healthz did not respond in 3s"
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
  *) echo "usage: $0 {start|stop|restart|status|tail}"; exit 2 ;;
esac
