#!/usr/bin/env bash
# FEAT-06: Apply VSPUXState to UEBA panel (Sprint 5.2)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/06-ueba-uxstates/06_patch.py
echo ""
echo "=== Verify ==="
head -1 static/panels/ueba.html
echo "Empty arrays:     $(grep -cE "var (SAMPLE|SCORE_HIST)=\[\];|var BL_SCORE=null;" static/panels/ueba.html)"
echo "Mock removed:     $(grep -c "Security score dropped 50pts" static/panels/ueba.html)"
echo "VSPUXState calls: $(grep -c "VSPUXState\." static/panels/ueba.html)"
echo "loadAnomalies:    $(grep -c "async function loadAnomalies" static/panels/ueba.html)"
echo ""
echo "Browser hard-reload required: Ctrl+Shift+R on https://vsp.local"
