#!/usr/bin/env bash
set -euo pipefail
BIN="${VSP_DAST_BIN:-./vsp-dast-api}"
ADDR="${VSP_DAST_ADDR:-:8093}"
STORE="${VSP_DAST_STORE:-/var/lib/vsp/dast-scans.json}"
LOG="${VSP_DAST_LOG:-/var/log/vsp/dast.log}"
PIDF="${VSP_DAST_PID:-/var/run/vsp/dast.pid}"
PARALLEL="${VSP_DAST_PARALLEL:-1}"

[[ -w "$(dirname "$LOG")" ]] || { LOG=/tmp/vsp-runtime/dast.log; mkdir -p /tmp/vsp-runtime; }
[[ -w "$(dirname "$PIDF")" ]] || { PIDF=/tmp/vsp-runtime/dast.pid; mkdir -p /tmp/vsp-runtime; }

is_running() { [[ -f "$PIDF" ]] && kill -0 "$(<"$PIDF")" 2>/dev/null; }

case "${1:-start}" in
  start)
    is_running && { echo "✓ already running (pid=$(<"$PIDF"))"; exit 0; }
    [[ -x "$BIN" ]] || { echo "✗ $BIN not built — run: go build -o vsp-dast-api ./cmd/dast-api"; exit 2; }

    echo "→ Pre-flight"
    if command -v nuclei >/dev/null; then
      echo "  ✓ nuclei: $(command -v nuclei)"
    else
      echo "  ⚠ nuclei NOT on PATH"
      echo "    install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
      echo "    then:    nuclei -update-templates"
    fi

    echo "→ starting on $ADDR  log=$LOG  parallel=$PARALLEL"
    setsid nohup "$BIN" -addr "$ADDR" -store "$STORE" -parallel "$PARALLEL" >>"$LOG" 2>&1 &
    pid=$!; disown "$pid" 2>/dev/null || true; echo "$pid" > "$PIDF"
    sleep 0.5
    for i in 1 2 3 4 5; do
      if curl -sf "http://127.0.0.1${ADDR}/healthz" >/dev/null 2>&1; then
        echo "✓ vsp-dast-api up (pid=$pid)"
        curl -s "http://127.0.0.1${ADDR}/healthz" | head -c 400; echo
        exit 0
      fi
      sleep 0.5
    done
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
