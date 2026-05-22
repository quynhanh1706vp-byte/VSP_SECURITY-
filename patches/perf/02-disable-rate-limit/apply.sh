#!/usr/bin/env bash
# PERF-02 — Disable per-user rate limit on /api/v1/* group
#
# Run from repo root: bash patches/perf/02-disable-rate-limit/apply.sh
set -euo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

if [ ! -f go.mod ]; then
  echo "ERROR: not at repo root"; exit 2
fi

TARGET_GO=cmd/gateway/main.go
TARGET_GI=.gitignore

# Backups (idempotent — only create once)
for f in "$TARGET_GO" "$TARGET_GI"; do
  bak="$f.bak.perf02"
  if [ ! -f "$bak" ]; then
    cp "$f" "$bak"
    echo "✓ Backup: $bak"
  else
    echo "↻ Backup exists: $bak (not overwriting)"
  fi
done

# Apply (handles both main.go + .gitignore)
python3 "$SCRIPT_DIR/perf02_patch.py" "$REPO_ROOT"

# Verify
echo ""
echo "Verification:"
if grep -q "VSP_PATCH_PERF_02" "$TARGET_GO"; then
  echo "  ✓ main.go marker present"
fi
N_ACTIVE=$(grep -cE "^[[:space:]]*r\.Use\(vspMW\.NewUserRateLimiter" "$TARGET_GO" || true)
echo "  active NewUserRateLimiter() calls: $N_ACTIVE (expect 0)"

if grep -q "!patches/perf/" "$TARGET_GI"; then
  echo "  ✓ .gitignore whitelists patches/perf/"
fi

# Test git can see the patch dir
if git -C "$REPO_ROOT" check-ignore -q patches/perf/02-disable-rate-limit/apply.sh 2>/dev/null; then
  echo "  ⚠ git STILL ignores patches/perf/ — manual fix needed"
else
  echo "  ✓ git can track patches/perf/"
fi

if [ "$N_ACTIVE" != "0" ]; then
  echo "⚠ WARN: rate limiter still active in main.go — review manually"
  exit 1
fi

cat <<'EOF'

╭─ NEXT STEPS ──────────────────────────────────────────────────────────╮
│                                                                        │
│ 1. Build gateway:                                                      │
│      bash scripts/build-gateway.sh                                    │
│                                                                        │
│ 2. Stop service, install binary, start:                               │
│      sudo systemctl stop vsp-gateway                                  │
│      sleep 2                                                           │
│      sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway   │
│      sudo systemctl start vsp-gateway                                 │
│      sleep 3                                                           │
│      sudo systemctl status vsp-gateway --no-pager | head -5           │
│                                                                        │
│ 3. Browser test:                                                      │
│      Hard-reload (Ctrl+Shift+R)                                       │
│      Console: ZERO 429 errors                                         │
│      KPI cards populate (1865 findings, GATE FAIL etc.)               │
│      Findings tab → tick CVE → Resolve → green toast                  │
│                                                                        │
│ Commit:                                                               │
│   git add patches/perf/                                               │
│   git add cmd/gateway/main.go .gitignore                              │
│   git status                                                           │
│   git commit -m "perf(gateway): disable per-user rate limit on /api/v1 (PERF-02)" │
│   git push origin docs/security-deliverables                          │
│                                                                        │
│ Rollback:                                                             │
│   bash patches/perf/02-disable-rate-limit/rollback.sh                 │
│   bash scripts/build-gateway.sh                                       │
│   sudo systemctl stop vsp-gateway && sleep 2                          │
│   sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway      │
│   sudo systemctl start vsp-gateway                                    │
╰───────────────────────────────────────────────────────────────────────╯

EOF

echo "✅ PERF-02 patch applied. Rebuild + redeploy gateway."
