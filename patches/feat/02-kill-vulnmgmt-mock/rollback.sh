#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
BACKUP="static/panels/vuln_mgmt.html.bak.feat02"
[[ -f "$BACKUP" ]] || { echo "Backup not found: $BACKUP"; exit 1; }
cp "$BACKUP" static/panels/vuln_mgmt.html
echo "Restored static/panels/vuln_mgmt.html from $BACKUP"
echo "Browser hard-reload required: Ctrl+Shift+R"
