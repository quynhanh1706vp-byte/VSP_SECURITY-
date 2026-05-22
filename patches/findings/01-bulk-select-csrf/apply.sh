#!/usr/bin/env bash
# F1.1 — CSRF Header Patch
# Adds X-CSRF-Token header (double-submit pattern) to bulk action POSTs.
#
# Run from repo root: bash patches/findings/01-bulk-select-csrf/apply.sh
set -euo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

if [ ! -f go.mod ]; then
  echo "ERROR: not at repo root"; exit 2
fi

TARGET="static/js/vsp_bulk_f1.js"
if [ ! -f "$TARGET" ]; then
  echo "ERROR: $TARGET not found — apply F1 first"; exit 2
fi

# Backup
BAK="$TARGET.bak.f1csrf"
if [ ! -f "$BAK" ]; then
  cp "$TARGET" "$BAK"
  echo "✓ Backup: $BAK"
else
  echo "↻ Backup exists: $BAK (not overwriting)"
fi

# Apply
python3 "$SCRIPT_DIR/csrf_patch.py" "$TARGET"

# Verify
echo ""
echo "Verification:"
if grep -q "VSP_F1_CSRF_PATCHED" "$TARGET"; then
  echo "  ✓ marker present"
fi
N_CRED=$(grep -c "credentials: 'include'" "$TARGET" || true)
N_HDR=$(grep -c "vspCsrfHeaders" "$TARGET" || true)
echo "  credentials:'include' occurrences: $N_CRED (expect 2)"
echo "  vspCsrfHeaders occurrences:        $N_HDR (expect 3 — 1 def + 2 calls)"

if [ "$N_CRED" != "2" ] || [ "$N_HDR" != "3" ]; then
  echo "⚠ WARN: counts off — review $TARGET manually"
fi

cat <<'EOF'

╭─ NEXT STEPS ──────────────────────────────────────────────────────────╮
│                                                                        │
│ 1. Hard-reload browser (Ctrl+Shift+R) to bypass JS cache              │
│ 2. Open DevTools → Application → Cookies → vsp.local                  │
│      Verify "vsp_csrf" cookie exists                                  │
│      (if missing, GET / on the page first to get the cookie issued)   │
│ 3. Findings tab → tick CVE → click Resolve                            │
│      Expected: green toast "Resolved 1 CVE ✓"                         │
│ 4. DevTools → Network tab → /api/v1/vulns/bulk request                │
│      Verify request headers include "X-CSRF-Token"                    │
│      Verify response status is 200                                    │
│                                                                        │
│ Commit:                                                               │
│   git add patches/findings/01-bulk-select-csrf/                       │
│   git add static/js/vsp_bulk_f1.js                                    │
│   git commit -m "fix(findings): add CSRF header to bulk action POSTs (F1.1)" │
│   git push origin docs/security-deliverables                          │
│                                                                        │
│ Rollback:                                                             │
│   bash patches/findings/01-bulk-select-csrf/rollback.sh               │
╰───────────────────────────────────────────────────────────────────────╯

EOF

echo "✅ F1.1 CSRF patch applied."
