#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/mint_jwt.sh [role] [port]
ROLE=${1:-admin}
PORT=${2:-8090}

RESP=$(curl -sS -X POST "http://localhost:${PORT}/api/v1/auth/mint" -H 'Content-Type: application/json' -d "{\"role\":\"${ROLE}\"}")
if command -v jq > /dev/null 2>&1; then
	echo "$RESP" | jq -r .token
else
	echo "$RESP" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
fi
