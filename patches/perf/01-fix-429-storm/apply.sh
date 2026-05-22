#!/usr/bin/env bash
# PERF-01 — Fix 429 storm
# Bumps per-user rate limit 600 → 3000 req/min in cmd/gateway/main.go.
#
# Run from repo root: bash patches/perf/01-fix-429-storm/apply.sh
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
BAK="$TARGET.bak.perf01"
if [ ! -f "$BAK" ]; then
  cp "$TARGET" "$BAK"
  echo "✓ Backup: $BAK"
else
  echo "↻ Backup exists: $BAK (not overwriting)"
fi

# Apply
python3 "$SCRIPT_DIR/perf_patch.py" "$TARGET"

# Verify
echo ""
echo "Verification:"
if grep -q "VSP_PATCH_PERF_01" "$TARGET"; then
  echo "  ✓ marker present"
fi
N_3000=$(grep -c "NewUserRateLimiter(3000, time.Minute)" "$TARGET" || true)
N_600=$(grep -c "NewUserRateLimiter(600, time.Minute)" "$TARGET" || true)
echo "  3000-rate occurrences: $N_3000 (expect 1)"
echo "  600-rate occurrences:  $N_600 (expect 0)"

if [ "$N_3000" != "1" ] || [ "$N_600" != "0" ]; then
  echo "⚠ WARN: counts off — review $TARGET manually"
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
│ 3. Verify in browser:                                                 │
│      Hard-reload (Ctrl+Shift+R)                                       │
│      Console should show NO 429 errors during dashboard boot          │
│      KPI cards should populate (no longer 0/0/0)                      │
│                                                                        │
│ Commit:                                                               │
│   git add patches/perf/01-fix-429-storm/                              │
│   git add cmd/gateway/main.go                                         │
│   git commit -m "perf(gateway): bump rate limit 600 → 3000 (PERF-01)" │
│   git push origin docs/security-deliverables                          │
│                                                                        │
│ Rollback:                                                             │
│   bash patches/perf/01-fix-429-storm/rollback.sh                      │
│   (then rebuild + redeploy gateway)                                   │
╰───────────────────────────────────────────────────────────────────────╯

EOF

echo "✅ PERF-01 patch applied. Build + deploy per steps above."
