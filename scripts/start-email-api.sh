#!/usr/bin/env bash
set -euo pipefail
BIN="${VSP_EMAIL_BIN:-./vsp-email-api}"
ADDR="${VSP_EMAIL_ADDR:-:8095}"
CFG="${VSP_EMAIL_CONFIG:-/var/lib/vsp/email-config.json}"
HIST="${VSP_EMAIL_HISTORY:-/var/lib/vsp/email-history.json}"
LOG="${VSP_EMAIL_LOG:-/var/log/vsp/email.log}"
PIDF="${VSP_EMAIL_PID:-/var/run/vsp/email.pid}"

[[ -w "$(dirname "$LOG")" ]] || { LOG=/tmp/vsp-runtime/email.log; mkdir -p /tmp/vsp-runtime; }
[[ -w "$(dirname "$PIDF")" ]] || { PIDF=/tmp/vsp-runtime/email.pid; mkdir -p /tmp/vsp-runtime; }

is_running() { [[ -f "$PIDF" ]] && kill -0 "$(<"$PIDF")" 2>/dev/null; }

case "${1:-start}" in
  start)
    is_running && { echo "✓ already running (pid=$(<"$PIDF"))"; exit 0; }
    [[ -x "$BIN" ]] || { echo "✗ $BIN not built"; exit 2; }
    echo "→ starting on $ADDR  log=$LOG"
    setsid nohup "$BIN" -addr "$ADDR" -config "$CFG" -history "$HIST" >>"$LOG" 2>&1 &
    pid=$!; disown "$pid" 2>/dev/null || true; echo "$pid" > "$PIDF"
    sleep 0.5
    for i in 1 2 3 4 5; do
      if curl -sf "http://127.0.0.1${ADDR}/healthz" >/dev/null 2>&1; then
        echo "✓ vsp-email-api up (pid=$pid)"
        curl -s "http://127.0.0.1${ADDR}/healthz"; echo
        exit 0
      fi
      sleep 0.5
    done
    echo "⚠ slow start, log:"
    tail -10 "$LOG" 2>/dev/null | sed 's/^/  /'
    ;;
  stop)
    is_running || { echo "· not running"; rm -f "$PIDF"; exit 0; }
    pid=$(<"$PIDF"); echo "→ stopping pid=$pid"
    kill -TERM "$pid" 2>/dev/null || true
    for i in 1 2 3 4 5; do sleep 0.5; kill -0 "$pid" 2>/dev/null || { echo "✓ stopped"; rm -f "$PIDF"; exit 0; }; done
    kill -KILL "$pid" 2>/dev/null || true; rm -f "$PIDF"
    ;;
  restart) "$0" stop; sleep 0.3; "$0" start ;;
  status)
    is_running && echo "✓ running (pid=$(<"$PIDF"))" || { echo "✗ not running"; exit 1; }
    curl -s "http://127.0.0.1${ADDR}/healthz" 2>/dev/null; echo
    ;;
  tail) tail -F "$LOG" ;;
  *) echo "usage: $0 {start|stop|restart|status|tail}"; exit 2 ;;
esac
