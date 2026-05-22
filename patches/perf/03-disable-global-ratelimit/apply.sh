#!/usr/bin/env bash
# PERF-03 — Disable global per-IP rate limiter
#
# Run from repo root: bash patches/perf/03-disable-global-ratelimit/apply.sh
set -euo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

if [ ! -f go.mod ]; then
  echo "ERROR: not at repo root"; exit 2
fi

TARGET="cmd/gateway/main.go"
if [ ! -f "$TARGET" ]; then
  echo "ERROR: $TARGET not found"; exit 2
fi

# Backup
BAK="$TARGET.bak.perf03"
if [ ! -f "$BAK" ]; then
  cp "$TARGET" "$BAK"
  echo "✓ Backup: $BAK"
else
  echo "↻ Backup exists: $BAK (not overwriting)"
fi

# Apply
python3 "$SCRIPT_DIR/perf03_patch.py" "$TARGET"

# Verify
echo ""
echo "Verification:"
if grep -q "VSP_PATCH_PERF_03" "$TARGET"; then
  echo "  ✓ marker present"
fi

# Active (non-commented) rate limiter sites should both be 0
N_INIT=$(grep -cE "^\s*rl\s*:=\s*vspMW\.NewRateLimiter" "$TARGET" || true)
N_USE=$(grep -cE "^\s*r\.Use\(rl\.Middleware\)" "$TARGET" || true)
echo "  active rl init lines:  $N_INIT (expect 0)"
echo "  active rl.Middleware uses: $N_USE (expect 0)"

if [ "$N_INIT" != "0" ] || [ "$N_USE" != "0" ]; then
  echo "⚠ WARN: rate limiter still active — review $TARGET manually"
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
│ 3. Browser hard-reload (Ctrl+Shift+R):                                │
│      Console: ZERO 429 errors (this should be the FINAL fix)          │
│      KPI cards populate immediately                                   │
│      F1 bulk action → green toast                                     │
│                                                                        │
│ Commit:                                                               │
│   git add patches/perf/ cmd/gateway/main.go                           │
│   git commit -m "perf(gateway): disable global IP rate limiter (PERF-03)" │
│   git push origin docs/security-deliverables                          │
│                                                                        │
│ Rollback:                                                             │
│   bash patches/perf/03-disable-global-ratelimit/rollback.sh           │
│   bash scripts/build-gateway.sh                                       │
│   sudo systemctl stop vsp-gateway && sleep 2                          │
│   sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway      │
│   sudo systemctl start vsp-gateway                                    │
╰───────────────────────────────────────────────────────────────────────╯

EOF

echo "✅ PERF-03 patch applied. Rebuild + redeploy gateway."
