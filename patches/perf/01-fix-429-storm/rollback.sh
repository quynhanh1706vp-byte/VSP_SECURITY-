#!/usr/bin/env bash
# PERF-01 rollback
set -euo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

TARGET="cmd/gateway/main.go"
BAK="$TARGET.bak.perf01"

if [ -f "$BAK" ]; then
  cp "$BAK" "$TARGET"
  echo "✓ Restored $TARGET from $BAK"
  echo "  Delete backup with: rm $BAK"
else
  echo "WARN: $BAK not found — attempting marker-based undo"
  python3 - <<'PY'
import re, sys
p = "cmd/gateway/main.go"
src = open(p, encoding="utf-8").read()
if "VSP_PATCH_PERF_01" not in src:
    print("Nothing to undo (marker absent)")
    sys.exit(0)
new = re.sub(
    r"\t// VSP_PATCH_PERF_01 — bumped 600 → 3000 to absorb dashboard burst \(panel fan-out ~50 req/3s\)\n"
    r"\tr\.Use\(vspMW\.NewUserRateLimiter\(3000, time\.Minute\)\) // per-user: 3000 req/min",
    "\tr.Use(vspMW.NewUserRateLimiter(600, time.Minute)) // per-user: 600 req/min",
    src
)
open(p, "w", encoding="utf-8").write(new)
print("✓ Reverted to 600 req/min by markers")
PY
fi

echo "✅ PERF-01 rolled back. Rebuild + redeploy gateway:"
echo "   bash scripts/build-gateway.sh"
echo "   sudo systemctl stop vsp-gateway && sleep 2"
echo "   sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway"
echo "   sudo systemctl start vsp-gateway"
