#!/usr/bin/env bash
# PERF-03 rollback
set -euo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

TARGET="cmd/gateway/main.go"
BAK="$TARGET.bak.perf03"

if [ -f "$BAK" ]; then
  cp "$BAK" "$TARGET"
  echo "✓ Restored $TARGET from $BAK"
  echo "  Delete backup: rm $BAK"
else
  echo "WARN: $BAK not found — attempting marker-based undo"
  python3 - <<'PY'
import re, sys
p = "cmd/gateway/main.go"
src = open(p, encoding="utf-8").read()
if "VSP_PATCH_PERF_03" not in src:
    print("Nothing to undo (marker absent)")
    sys.exit(0)

# Restore rl init block
init_old = re.compile(
    r"\t// VSP_PATCH_PERF_03 — global per-IP rate limiter disabled\..*?"
    r"// rl := vspMW\.NewRateLimiter\(600, time\.Minute\)",
    re.DOTALL
)
src = init_old.sub("\trl := vspMW.NewRateLimiter(600, time.Minute)", src, count=1)

# Restore r.Use(rl.Middleware)
src = src.replace(
    "\t// VSP_PATCH_PERF_03 — disabled: r.Use(rl.Middleware)",
    "\tr.Use(rl.Middleware)",
    1,
)
open(p, "w", encoding="utf-8").write(src)
print("✓ Reverted main.go via markers")
PY
fi

echo ""
echo "✅ PERF-03 rolled back. Rebuild + redeploy gateway:"
echo "   bash scripts/build-gateway.sh"
echo "   sudo systemctl stop vsp-gateway && sleep 2"
echo "   sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway"
echo "   sudo systemctl start vsp-gateway"
