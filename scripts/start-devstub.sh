#!/usr/bin/env bash
set -euo pipefail

# Build and start the dev-stub in a stable, detached way.
# If an instance is already running, tail its log.

PORT=${DEVSTUB_PORT:-8090}
LOG="dev-stub-${PORT}.log"
BINARY="./vsp-dev-stub"

echo "checking for existing dev-stub..."
EXISTING_PID=$(pgrep -f vsp-dev-stub || true)
if [ -n "${EXISTING_PID}" ]; then
  echo "dev-stub already running (pid=${EXISTING_PID}); tailing ${LOG}"
  tail -n 200 "${LOG}" || true
  exit 0
fi

echo "building dev-stub..."
go build -tags devstub -o vsp-dev-stub ./cmd/dev-stub

# choose a free port if requested port is in use
if ss -ltn | awk '{print $4}' | grep -q ":${PORT}$"; then
  echo "port ${PORT} already in use; searching for free port 8090..8190"
  for p in $(seq 8090 8190); do
    if ! ss -ltn | awk '{print $4}' | grep -q ":${p}$"; then
      PORT=${p}
      LOG="dev-stub-${PORT}.log"
      echo "selected free port ${PORT}"
      break
    fi
  done
fi

export DEVSTUB_PORT=${PORT}

echo "starting dev-stub on port ${PORT}, logging -> ${LOG}"
nohup setsid env DEVSTUB_PORT=${PORT} ${BINARY} > "${LOG}" 2>&1 &
sleep 0.6
NEWPID=$(pgrep -f vsp-dev-stub || true)
echo "started pid=${NEWPID}"
echo "--- last 200 lines of ${LOG} ---"
tail -n 200 "${LOG}" || true

echo "Done. Use scripts/stop-devstub.sh to stop."
