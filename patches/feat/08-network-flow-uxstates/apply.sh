#!/usr/bin/env bash
# FEAT-08: Apply VSPUXState to Network Flow panel (Sprint 5.4 — Phase A final)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/08-network-flow-uxstates/08_patch.py
echo ""
echo "=== Verify ==="
head -1 static/panels/network_flow.html
echo "Empty arrays:     $(grep -cE "var (CONNS|PROTOS|NDR_ALERTS)=\[\];" static/panels/network_flow.html)"
echo "Mock connection:  $(grep -c "src:'185.220.101.47'" static/panels/network_flow.html)"
echo "VSPUXState calls: $(grep -c "VSPUXState\." static/panels/network_flow.html)"
echo ""
echo "Browser hard-reload required: Ctrl+Shift+R on https://vsp.local"
