#!/usr/bin/env bash
# FEAT-10 (Sprint 6): Apply VSPUXState to Threat Intel panel — Phase B start
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/09-threat-intel-uxstates/09_patch.py
echo ""
echo "=== Verify ==="
head -1 static/panels/threat_intel.html
echo "Empty arrays:     $(grep -cE "var (IOCS|FEEDS|CVES)=\[\];" static/panels/threat_intel.html)"
echo "VSPUXState calls: $(grep -c "VSPUXState\." static/panels/threat_intel.html)"
echo "CVES endpoint:    $(grep -c "/api/v1/vulns/top-cves" static/panels/threat_intel.html)"
echo ""
echo "Browser hard-reload required: Ctrl+Shift+R on https://vsp.local"
