#!/usr/bin/env bash
# F1 — Bulk Select Apply Script v2 (Strategy C+ additive)
# Run from repo root: bash patches/findings/01-bulk-select/apply.sh
set -euo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

HTML="static/panels/vuln_mgmt.html"
JS_DIR="static/js"
SRC_JS="$SCRIPT_DIR/vsp_bulk_f1.js"

# ── Sanity ─────────────────────────────────────────────────────────────
if [ ! -f "go.mod" ]; then
  echo "ERROR: not at repo root (no go.mod found at $REPO_ROOT)"; exit 2
fi
if [ ! -f "$HTML" ]; then
  echo "ERROR: $HTML not found"; exit 2
fi
if [ ! -f "$SRC_JS" ]; then
  echo "ERROR: $SRC_JS not found"; exit 2
fi

# ── Backup HTML ────────────────────────────────────────────────────────
BAK="$HTML.bak.f1"
if [ ! -f "$BAK" ]; then
  cp "$HTML" "$BAK"
  echo "✓ HTML backup: $BAK"
else
  echo "↻ HTML backup exists: $BAK (not overwriting)"
fi

# ── Apply ──────────────────────────────────────────────────────────────
echo "▸ Installing JS + patching HTML ..."
python3 "$SCRIPT_DIR/frontend.py" "$HTML" "$JS_DIR" "$SRC_JS"

# ── Backend instructions ───────────────────────────────────────────────
cat <<EOF

╭─ MANUAL STEP — backend handler ──────────────────────────────────────╮
│ Open: cmd/dev-stub/main.go                                           │
│ Copy the snippet from:                                               │
│   $SCRIPT_DIR/backend.go.snippet
│ Paste it ABOVE the line that registers other handlers (look for     │
│ existing 'mux.HandleFunc("/api/v1/' or similar).                    │
│ Then register the routes by adding these 2 lines:                    │
│                                                                      │
│   mux.HandleFunc("/api/v1/vulns/bulk",      handleVulnsBulk)        │
│   mux.HandleFunc("/api/v1/vulns/bulk/undo", handleVulnsBulkUndo)    │
│                                                                      │
│ Optionally in main(): go cleanupBulkUndoStore()                      │
│ Then rebuild & restart:                                              │
│   go build -o vsp-gateway ./cmd/dev-stub                             │
│   sudo systemctl restart vsp-gateway                                 │
╰──────────────────────────────────────────────────────────────────────╯

EOF

# ── Status ─────────────────────────────────────────────────────────────
echo "▸ Diff stat:"
if command -v git >/dev/null 2>&1 && [ -d ".git" ]; then
  git diff --stat -- "$HTML" "$JS_DIR/vsp_bulk_f1.js" 2>/dev/null || true
fi

cat <<EOF

✅ Frontend patch F1 applied.

Next:
  1. Verify file changes:
       git status
       git diff static/panels/vuln_mgmt.html
       ls static/js/vsp_bulk_f1.js
  2. Open browser → https://vsp.local/static/panels/vuln_mgmt.html
       (or via parent iframe by clicking Findings tab)
  3. Verify checkbox column appears, action bar slides up on click
  4. Apply backend snippet (see manual step above)
  5. Test bulk action — should see toast + undo banner
  6. If all OK:
       git add patches/findings/01-bulk-select/ \\
               static/panels/vuln_mgmt.html \\
               static/js/vsp_bulk_f1.js \\
               cmd/dev-stub/main.go
       git commit -m "feat(findings): bulk select + bulk actions toolbar (F1)"
       git push origin docs/security-deliverables

If anything looks wrong:
  bash patches/findings/01-bulk-select/rollback.sh
EOF
