#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
BACKUP="static/panels/threat_intel.html.bak.feat09"
[[ -f "$BACKUP" ]] || { echo "Backup not found: $BACKUP"; exit 1; }
cp "$BACKUP" static/panels/threat_intel.html
echo "Restored static/panels/threat_intel.html from $BACKUP"
