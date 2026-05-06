#!/usr/bin/env bash
# FEAT-05: Apply VSPUXState to Users panel
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/05-users-uxstates/05_patch.py
echo ""
echo "=== Verify ==="
head -1 static/panels/users.html
echo "Empty USERS+ROLES:    $(grep -cE "var (USERS|ROLES)=\[\];" static/panels/users.html)"
echo "VSPUXState calls:     $(grep -c "VSPUXState\." static/panels/users.html)"
echo "loadRoles fn:         $(grep -c "async function loadRoles" static/panels/users.html)"
echo ""
echo "Browser hard-reload required: Ctrl+Shift+R on https://vsp.local"
