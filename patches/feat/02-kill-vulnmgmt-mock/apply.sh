#!/usr/bin/env bash
# FEAT-02: Kill hardcoded mock data in vuln_mgmt.html
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/02-kill-vulnmgmt-mock/02_patch.py
echo ""
echo "=== Verify ==="
head -1 static/panels/vuln_mgmt.html
echo "Empty SAMPLE_*  count: $(grep -cE "var SAMPLE_\w+ = \[\];" static/panels/vuln_mgmt.html)"
echo "Mock CVE-2023-44487:   $(grep -c "HTTP/2 Rapid Reset" static/panels/vuln_mgmt.html)"
echo "Helpers injected:      $(grep -c "FEAT-02 helpers" static/panels/vuln_mgmt.html)"
echo ""
echo "Browser hard-reload required: Ctrl+Shift+R on https://vsp.local"
