#!/usr/bin/env bash
# FEAT-04: Create shared VSPUXState module + inject into index.html
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/04-uxstates-module/04_patch.py
echo ""
echo "=== Verify ==="
ls -la static/vsp_uxstates.js static/js/vsp_uxstates.js | awk '{print $5, $NF}'
echo "Marker in index: $(grep -c "FEAT-04: VSPUXState" static/index.html)"
echo "Script tag:      $(grep -c "vsp_uxstates.js" static/index.html)"
echo ""
echo "Browser hard-reload required: Ctrl+Shift+R on https://vsp.local"
echo "Smoke test: paste in DevTools console:"
echo "  console.log(typeof VSPUXState, VSPUXState && Object.keys(VSPUXState))"
