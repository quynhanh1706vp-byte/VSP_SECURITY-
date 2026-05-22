#!/usr/bin/env bash
# FEAT-07: Apply VSPUXState to Threat Hunt panel (Sprint 5.3)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/07-threat-hunt-uxstates/07_patch.py
echo ""
echo "=== Verify ==="
head -1 static/panels/threat_hunt.html
echo "VSPUXState calls: $(grep -c "VSPUXState\." static/panels/threat_hunt.html)"
echo "typeof guards:    $(grep -c "typeof VSPUXState" static/panels/threat_hunt.html)"
echo ""
echo "Browser hard-reload required: Ctrl+Shift+R on https://vsp.local"
