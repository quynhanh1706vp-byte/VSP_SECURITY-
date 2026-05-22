#!/usr/bin/env bash
# FEAT-03: Kill hardcoded mock data in scheduler.html
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/03-kill-scheduler-mock/03_patch.py
echo ""
echo "=== Verify ==="
head -1 static/panels/scheduler.html
echo "Empty SAMPLE_*:    $(grep -cE "var SAMPLE_(SCHEDS|RUNS) = \[\];" static/panels/scheduler.html)"
echo "Mock RID_SCHED:    $(grep -c "RID_SCHED_2026" static/panels/scheduler.html)"
echo "Helpers injected:  $(grep -c "FEAT-03 helpers" static/panels/scheduler.html)"
echo ""
echo "Browser hard-reload required: Ctrl+Shift+R on https://vsp.local"
