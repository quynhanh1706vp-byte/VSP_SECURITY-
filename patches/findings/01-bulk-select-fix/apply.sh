#!/usr/bin/env bash
# F1 Super-Patch Apply — fixes 3 issues at once:
#   1. .gitignore blocks F1 files (patches/, vsp_*.js)
#   2. Backend handler missing (HTTP 404 on /api/v1/vulns/bulk)
#   3. (Optional) Stage F1 files for amend-commit
#
# Run from repo root: bash patches/findings/01-bulk-select-fix/apply.sh
set -euo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

if [ ! -f go.mod ]; then
  echo "ERROR: not at repo root (no go.mod)"; exit 2
fi

GW_MAIN="cmd/gateway/main.go"
GW_DIR="cmd/gateway"
SRC_GO="$SCRIPT_DIR/bulk_findings.go"

if [ ! -f "$GW_MAIN" ]; then
  echo "ERROR: $GW_MAIN not found — is this the right repo?"; exit 2
fi
if [ ! -f "$SRC_GO" ]; then
  echo "ERROR: $SRC_GO not in patch dir"; exit 2
fi

# ────────────────────────────────────────────────────────────────────
# Step 1: Fix .gitignore
# ────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════════════════"
echo " Step 1/3: Fix .gitignore"
echo "════════════════════════════════════════════════════════"
python3 "$SCRIPT_DIR/01_fix_gitignore.py" .gitignore

# ────────────────────────────────────────────────────────────────────
# Step 2: Backup main.go + inject backend
# ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo " Step 2/3: Inject backend routes into $GW_MAIN"
echo "════════════════════════════════════════════════════════"
BAK="$GW_MAIN.bak.f1"
if [ ! -f "$BAK" ]; then
  cp "$GW_MAIN" "$BAK"
  echo "✓ Backup: $BAK"
else
  echo "↻ Backup exists: $BAK (not overwriting)"
fi

python3 "$SCRIPT_DIR/02_inject_routes.py" "$GW_MAIN" "$GW_DIR" "$SRC_GO"

# ────────────────────────────────────────────────────────────────────
# Step 3: Verify gitignore + show next manual steps
# ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo " Step 3/3: Verification"
echo "════════════════════════════════════════════════════════"

CHECKS=(
  "patches/findings/01-bulk-select/vsp_bulk_f1.js"
  "patches/findings/01-bulk-select/README.md"
  "static/js/vsp_bulk_f1.js"
  "cmd/gateway/bulk_findings.go"
  "cmd/gateway/main.go"
)
echo "File trackability:"
ALL_OK=1
for f in "${CHECKS[@]}"; do
  if [ ! -e "$f" ]; then
    echo "  ⊘ $f (not present — might be expected if F1 frontend not yet applied)"
    continue
  fi
  if git check-ignore -q "$f" 2>/dev/null; then
    echo "  ✗ $f STILL IGNORED — see 'git check-ignore -v $f'"
    ALL_OK=0
  else
    echo "  ✓ $f trackable"
  fi
done

echo ""
echo "Routes registered in main.go:"
grep -n "VSP_PATCH_F1_ROUTES\|/vulns/bulk" "$GW_MAIN" | head -5

# ────────────────────────────────────────────────────────────────────
# Next steps
# ────────────────────────────────────────────────────────────────────
cat <<EOF

╭─────────────────────────────────────────────────────────────────────╮
│ NEXT STEPS — manual                                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 1. Build & restart gateway:                                          │
│      bash scripts/build-gateway.sh                                   │
│      sudo cp bin/vsp-gateway /usr/local/bin/vsp-gateway              │
│      sudo systemctl restart vsp-gateway                              │
│                                                                      │
│ 2. Verify route is live (replace TOKEN with your bearer token):      │
│      curl -k -X POST https://vsp.local/api/v1/vulns/bulk \\           │
│        -H "Content-Type: application/json" \\                         │
│        -H "Authorization: Bearer \$TOKEN" \\                          │
│        -d '{"action":"resolve","cve_ids":["CVE-2025-32434"]}'        │
│      Expected: {"ok":true,"affected":1,"action_id":"act_...",...}    │
│                                                                      │
│ 3. Test in browser — Findings tab, tick CVE, click Resolve →         │
│      Toast "Resolved 1 CVE ✓" + undo banner                          │
│                                                                      │
│ 4. Amend the previous commit (ac70916) to include all F1 files:      │
│      git add .gitignore                                              │
│      git add patches/findings/01-bulk-select/                        │
│      git add static/js/vsp_bulk_f1.js                                │
│      git add cmd/gateway/main.go cmd/gateway/bulk_findings.go        │
│      git status         # review carefully                           │
│      git commit --amend --no-edit                                    │
│      git push --force-with-lease origin docs/security-deliverables   │
│                                                                      │
│   Or, if you prefer separate commits, drop --amend and write a new   │
│   commit message.                                                    │
│                                                                      │
│ Rollback:  bash patches/findings/01-bulk-select-fix/rollback.sh      │
╰─────────────────────────────────────────────────────────────────────╯

EOF

if [ "$ALL_OK" = "0" ]; then
  echo "⚠ Some files still ignored — review .gitignore manually before commit."
  exit 4
fi
echo "✅ Super-patch applied. Proceed with build + commit per steps above."
