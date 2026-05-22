#!/usr/bin/env bash
# F1.1 — CSRF Patch Rollback
set -euo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

TARGET="static/js/vsp_bulk_f1.js"
BAK="$TARGET.bak.f1csrf"

if [ -f "$BAK" ]; then
  cp "$BAK" "$TARGET"
  echo "✓ Restored $TARGET from $BAK"
  echo "  Delete backup with: rm $BAK"
else
  echo "WARN: $BAK not found — attempting marker-based undo"
  python3 - <<'PY'
import re, sys
p = "static/js/vsp_bulk_f1.js"
src = open(p, encoding="utf-8").read()
if "VSP_F1_CSRF_PATCHED" not in src:
    print("Nothing to undo (marker absent)")
    sys.exit(0)
# Remove helper block
src = re.sub(
    r"  // VSP_F1_CSRF_PATCHED.*?\n  function vspCsrfHeaders.*?^  \}\n",
    "", src, flags=re.DOTALL | re.MULTILINE)
# Revert POST patches
src = src.replace(
    "        credentials: 'include',\n"
    "        headers: vspCsrfHeaders({ 'Content-Type': 'application/json' }),\n",
    "        headers: { 'Content-Type': 'application/json' },\n")
open(p, "w", encoding="utf-8").write(src)
print("✓ Removed CSRF patch by markers")
PY
fi

echo "✅ F1.1 rolled back. Hard-reload browser to clear cached JS."
