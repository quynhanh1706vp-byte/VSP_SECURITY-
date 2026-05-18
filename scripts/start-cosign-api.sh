#!/usr/bin/env bash
# scripts/start-cosign-api.sh — v3
# ─────────────────────────────────────────────────────────────────────────
# Reliable launcher for vsp-cosign-api (port 8091).
# v3 adds: graceful fallback to /tmp/vsp-runtime if /var/* not writable
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

BIN="${VSP_COSIGN_BIN:-./vsp-cosign-api}"
ADDR="${VSP_COSIGN_ADDR:-:8091}"
KEYDIR="${VSP_COSIGN_KEYDIR:-/etc/vsp}"

# Pick writable runtime dirs: prefer /var/{lib,log,run}/vsp, fallback /tmp/vsp-runtime
pick_runtime() {
  local kind=$1 default=$2
  if [[ -d "$default" && -w "$default" ]]; then
    echo "$default"
  else
    local fb="/tmp/vsp-runtime/$kind"
    mkdir -p "$fb" 2>/dev/null
    echo "$fb"
  fi
}

STORE="${VSP_COSIGN_STORE:-$(pick_runtime store /var/lib/vsp)}"
LOG_DIR="$(pick_runtime log /var/log/vsp)"
PID_DIR="$(pick_runtime run /var/run/vsp)"
LOG="${VSP_COSIGN_LOG:-$LOG_DIR/cosign-api.log}"
PIDF="${VSP_COSIGN_PID:-$PID_DIR/cosign-api.pid}"

# Ensure writable
touch "$LOG" 2>/dev/null  || { LOG=/tmp/vsp-runtime/cosign-api.log; mkdir -p /tmp/vsp-runtime; touch "$LOG"; }
touch "$PIDF" 2>/dev/null || { PIDF=/tmp/vsp-runtime/cosign-api.pid; mkdir -p /tmp/vsp-runtime; touch "$PIDF"; rm -f "$PIDF"; }

is_running() {
  [[ -f "$PIDF" ]] || return 1
  local pid; pid=$(<"$PIDF")
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

preflight() {
  local errs=0
  echo "→ Pre-flight checks"

  # 1. Binary
  if [[ -x "$BIN" ]]; then
    echo "  ✓ binary $BIN"
  else
    echo "  ✗ binary $BIN missing or not executable"
    echo "    fix: go build -o vsp-cosign-api ./cmd/cosign-api"
    errs=$((errs+1))
  fi

  # 2. cosign CLI
  if command -v cosign >/dev/null; then
    echo "  ✓ cosign CLI: $(command -v cosign)"
  else
    echo "  ⚠ cosign CLI not on PATH (service still works, but verification skipped)"
  fi

  # 3. Keydir + access
  if [[ ! -d "$KEYDIR" ]]; then
    echo "  ✗ keydir $KEYDIR does not exist"
    echo "    fix: sudo ./scripts/setup-cosign-keys.sh"
    errs=$((errs+1))
  elif [[ ! -x "$KEYDIR" ]]; then
    local mode owner group
    mode=$(stat -c '%a' "$KEYDIR" 2>/dev/null || echo "?")
    owner=$(stat -c '%U' "$KEYDIR" 2>/dev/null || echo "?")
    group=$(stat -c '%G' "$KEYDIR" 2>/dev/null || echo "?")
    echo "  ✗ cannot enter $KEYDIR (mode $mode, owner $owner:$group)"
    echo "    current user: $(id -un)  groups: $(id -nG | tr ' ' ',')"
    if [[ "$group" == "vsp" ]]; then
      echo "    fix: not in group 'vsp' yet. Run:  exec sg vsp -c bash"
    fi
    errs=$((errs+1))
  else
    echo "  ✓ keydir $KEYDIR readable"
  fi

  # 4. Files
  if [[ -x "$KEYDIR" ]]; then
    for f in cosign.key cosign.pub cosign.pass; do
      if [[ -f "$KEYDIR/$f" ]]; then
        local mode size
        mode=$(stat -c '%a' "$KEYDIR/$f")
        size=$(stat -c '%s' "$KEYDIR/$f")
        echo "  ✓ $KEYDIR/$f  mode=$mode  size=$size"
        if [[ "$f" == "cosign.pass" ]]; then
          if [[ "$mode" != "640" ]]; then
            echo "    ✗ pass file mode is $mode — must be 0600"
            echo "      fix: sudo chmod 640 $KEYDIR/cosign.pass"
            errs=$((errs+1))
          fi
          if (( size < 1 )); then
            echo "    ✗ pass file empty"; errs=$((errs+1))
          elif (( size < 5 )); then
            echo "    ⚠ pass file very small ($size bytes) — looks like placeholder text"
            echo "      fix: echo -n 'YOUR_REAL_PASSWORD' | sudo tee $KEYDIR/cosign.pass >/dev/null"
            echo "           sudo chmod 640 $KEYDIR/cosign.pass"
          fi
        fi
      else
        echo "  ✗ $KEYDIR/$f missing"
        echo "    fix: sudo ./scripts/setup-cosign-keys.sh"
        errs=$((errs+1))
      fi
    done
  fi

  # 5. Runtime dirs writable
  echo "  ✓ runtime: log=$LOG"
  echo "             pid=$PIDF"
  echo "             store=$STORE"

  # 6. Port available
  local port="${ADDR#:}"
  if command -v ss >/dev/null && ss -ltn 2>/dev/null | grep -qE ":${port}\s"; then
    echo "  ⚠ port $port already in use:"
    ss -ltnp 2>/dev/null | grep -E ":${port}\s" | sed 's/^/      /'
  else
    echo "  ✓ port $port free"
  fi

  echo
  if (( errs > 0 )); then
    echo "✗ $errs check(s) failed — service will not start"
    return 1
  fi
  echo "✓ all checks passed"
  return 0
}

cmd_check() { preflight; }

cmd_start() {
  if is_running; then echo "✓ already running (pid=$(<"$PIDF"))"; return 0; fi
  preflight || exit 2

  echo "→ starting vsp-cosign-api on $ADDR"
  setsid nohup "$BIN" \
      -addr "$ADDR" \
      -keydir "$KEYDIR" \
      -store "$STORE" \
      >>"$LOG" 2>&1 &
  local pid=$!
  disown "$pid" 2>/dev/null || true
  echo "$pid" > "$PIDF"

  local i port="${ADDR#:}"
  for i in 1 2 3 4 5 6; do
    sleep 0.5
    if curl -sf "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      echo "✓ vsp-cosign-api up (pid=$pid)"
      curl -s "http://127.0.0.1:${port}/healthz"
      echo
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "✗ process died during startup — last 30 log lines:"
      tail -30 "$LOG" 2>/dev/null | sed 's/^/    /'
      rm -f "$PIDF"
      exit 1
    fi
  done
  echo "⚠ pid=$pid running but /healthz did not respond in 3s"
  echo "  log tail:"
  tail -10 "$LOG" 2>/dev/null | sed 's/^/    /'
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
  echo "⚠ SIGTERM ignored — sending SIGKILL"
  kill -KILL "$pid" 2>/dev/null || true
  rm -f "$PIDF"
}

cmd_status() {
  local port="${ADDR#:}"
  if is_running; then
    echo "✓ running (pid=$(<"$PIDF"))"
    curl -s "http://127.0.0.1:${port}/healthz" || echo "  /healthz not responding"
    echo
  else
    echo "✗ not running"; exit 1
  fi
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
