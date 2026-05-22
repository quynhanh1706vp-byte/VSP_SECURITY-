#!/usr/bin/env bash
# FEAT-12 (Sprint 8): Apply VSPUXState to Software Risk panel
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/11-software-risk-uxstates/11_patch.py
echo ""
echo "=== Verify ==="
head -1 static/panels/software_risk.html
echo "VSPUXState calls: $(grep -c "VSPUXState\." static/panels/software_risk.html)"
