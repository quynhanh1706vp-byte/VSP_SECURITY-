#!/usr/bin/env bash
# F1 Super-Patch Rollback
# Run from repo root: bash patches/findings/01-bulk-select-fix/rollback.sh
set -euo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

echo "Rolling back F1 super-patch..."

# 1. Restore main.go from backup (or remove markers)
GW_MAIN="cmd/gateway/main.go"
BAK="$GW_MAIN.bak.f1"
if [ -f "$BAK" ]; then
  cp "$BAK" "$GW_MAIN"
  echo "✓ Restored $GW_MAIN from $BAK"
elif grep -q "VSP_PATCH_F1_ROUTES_BEGIN" "$GW_MAIN"; then
  python3 -c "
import re, sys
p = '$GW_MAIN'
src = open(p, encoding='utf-8').read()
new = re.sub(
    r'^[ \t]*// VSP_PATCH_F1_ROUTES_BEGIN.*?// VSP_PATCH_F1_ROUTES_END\n',
    '', src, flags=re.DOTALL|re.MULTILINE)
open(p,'w',encoding='utf-8').write(new)
print('✓ Removed F1 markers from', p)
"
else
  echo "WARN: no backup, no markers — main.go may already be clean"
fi

# 2. Remove bulk_findings.go
if [ -f cmd/gateway/bulk_findings.go ]; then
  rm cmd/gateway/bulk_findings.go
  echo "✓ Removed cmd/gateway/bulk_findings.go"
fi
[ -f cmd/gateway/bulk_findings.go.bak.f1 ] && rm cmd/gateway/bulk_findings.go.bak.f1 || true

# 3. Restore .gitignore from backup
GIBAK=".gitignore.bak.f1"
if [ -f "$GIBAK" ]; then
  cp "$GIBAK" .gitignore
  echo "✓ Restored .gitignore from $GIBAK"
fi

cat <<'EOF'

╭─ MANUAL STEP — rebuild & redeploy ─────────────────────────────────╮
│ bash scripts/build-gateway.sh                                       │
│ sudo cp bin/vsp-gateway /usr/local/bin/vsp-gateway                  │
│ sudo systemctl restart vsp-gateway                                  │
╰────────────────────────────────────────────────────────────────────╯
EOF

echo "✅ Super-patch rolled back. Backups kept for safety:"
echo "   $BAK"
echo "   $GIBAK"
echo "   Delete with: rm $BAK $GIBAK"
