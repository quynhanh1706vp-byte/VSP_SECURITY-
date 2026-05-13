#!/usr/bin/env bash
set -euo pipefail

echo "stopping dev-stub processes (matching vsp-dev-stub)..."
pkill -f vsp-dev-stub || true
sleep 0.2
echo "done; ps entries:"
ps aux | egrep 'vsp-dev-stub|dev-stub' | egrep -v 'egrep' || true
