#!/usr/bin/env bash
# F1 — Rollback Script v2
# Run from repo root: bash patches/findings/01-bulk-select/rollback.sh
set -euo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

HTML="static/panels/vuln_mgmt.html"
JS="static/js/vsp_bulk_f1.js"
BAK="$HTML.bak.f1"

# ── Restore HTML ───────────────────────────────────────────────────────
if [ -f "$BAK" ]; then
  cp "$BAK" "$HTML"
  echo "✓ Restored $HTML from $BAK"
else
  echo "WARN: $BAK not found; attempting marker-based removal..."
  # Fallback: remove the inserted block by markers
  if grep -q "VSP_F1_SCRIPT_START" "$HTML"; then
    python3 -c "
import re, sys
p = '$HTML'
src = open(p, encoding='utf-8').read()
new = re.sub(r'<!-- VSP_F1_SCRIPT_START -->.*?<!-- VSP_F1_SCRIPT_END -->\n?', '', src, flags=re.DOTALL)
open(p, 'w', encoding='utf-8').write(new)
print('✓ Marker block removed from', p)
"
  else
    echo "ERROR: no backup and no markers found — nothing to do."
    exit 2
  fi
fi

# ── Remove JS ──────────────────────────────────────────────────────────
if [ -f "$JS" ]; then
  rm "$JS"
  echo "✓ Removed $JS"
fi
# Also remove .bak.f1 of JS if any earlier version was saved
[ -f "$JS.bak.f1" ] && rm "$JS.bak.f1" && echo "✓ Removed $JS.bak.f1" || true

cat <<'EOF'

╭─ MANUAL STEP — undo backend ────────────────────────────────────────╮
│ Open: cmd/dev-stub/main.go                                          │
│ Remove these (the // VSP_PATCH_F1 ... END VSP_PATCH_F1 block):     │
│   - func handleVulnsBulk(...)                                       │
│   - func handleVulnsBulkUndo(...)                                   │
│   - the bulkActionRecord type and undo store                        │
│   - their mux.HandleFunc registrations                              │
│ Then rebuild:                                                       │
│   go build -o vsp-gateway ./cmd/dev-stub                            │
╰─────────────────────────────────────────────────────────────────────╯

EOF

echo "✅ Frontend rolled back. HTML backup kept at $BAK."
echo "   Delete it after verifying: rm $BAK"
