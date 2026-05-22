#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
BACKUP="static/panels/users.html.bak.feat05"
[[ -f "$BACKUP" ]] || { echo "Backup not found: $BACKUP"; exit 1; }
cp "$BACKUP" static/panels/users.html
echo "Restored static/panels/users.html from $BACKUP"
echo "Browser hard-reload required: Ctrl+Shift+R"
