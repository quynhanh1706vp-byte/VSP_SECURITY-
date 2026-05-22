#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
BACKUP="static/panels/ueba.html.bak.feat06"
[[ -f "$BACKUP" ]] || { echo "Backup not found: $BACKUP"; exit 1; }
cp "$BACKUP" static/panels/ueba.html
echo "Restored static/panels/ueba.html from $BACKUP"
echo "Browser hard-reload required: Ctrl+Shift+R"
