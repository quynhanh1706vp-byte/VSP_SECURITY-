#!/usr/bin/env bash
# FEAT-01: Kill hardcoded mock data in assets.html
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/01-kill-assets-mock/01_patch.py
echo ""
echo "=== Verify ==="
head -1 static/panels/assets.html
echo "var ASSETS=[];   count: $(grep -c "var ASSETS=\[\];" static/panels/assets.html)"
echo "API Gateway mock count: $(grep -c "id:'a1',name:'API Gateway'" static/panels/assets.html)"
echo ""
echo "Browser hard-reload required: Ctrl+Shift+R on https://vsp.local"
