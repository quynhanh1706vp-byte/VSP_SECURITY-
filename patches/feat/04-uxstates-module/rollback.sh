#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
# Restore index.html
BAK_INDEX="static/index.html.bak.feat04"
if [[ -f "$BAK_INDEX" ]]; then
  cp "$BAK_INDEX" static/index.html
  echo "Restored static/index.html"
fi
# Remove shared JS files (no backups since they were new files)
rm -f static/vsp_uxstates.js static/js/vsp_uxstates.js
rm -f static/vsp_uxstates.js.bak.feat04 static/js/vsp_uxstates.js.bak.feat04
echo "Removed static/vsp_uxstates.js and static/js/vsp_uxstates.js"
echo "Browser hard-reload required: Ctrl+Shift+R"
