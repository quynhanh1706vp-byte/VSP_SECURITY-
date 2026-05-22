#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
BACKUP="static/panels/network_flow.html.bak.feat08"
[[ -f "$BACKUP" ]] || { echo "Backup not found: $BACKUP"; exit 1; }
cp "$BACKUP" static/panels/network_flow.html
echo "Restored static/panels/network_flow.html from $BACKUP"
