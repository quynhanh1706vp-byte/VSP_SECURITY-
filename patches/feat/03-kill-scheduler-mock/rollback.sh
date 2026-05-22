#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
BACKUP="static/panels/scheduler.html.bak.feat03"
[[ -f "$BACKUP" ]] || { echo "Backup not found: $BACKUP"; exit 1; }
cp "$BACKUP" static/panels/scheduler.html
echo "Restored static/panels/scheduler.html from $BACKUP"
echo "Browser hard-reload required: Ctrl+Shift+R"
