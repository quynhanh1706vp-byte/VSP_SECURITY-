#!/usr/bin/env bash
# FEAT-11 (Sprint 7): Apply VSPUXState to SBOM Diff panel
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/10-sbom-diff-uxstates/10_patch.py
echo ""
echo "=== Verify ==="
head -1 static/panels/sbom_diff.html
echo "VSPUXState calls: $(grep -c "VSPUXState\." static/panels/sbom_diff.html)"
