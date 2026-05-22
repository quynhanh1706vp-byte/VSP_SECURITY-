#!/usr/bin/env bash
# PERF-02 rollback — restore both main.go and .gitignore from backups
set -euo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

restored_any=0
for f in cmd/gateway/main.go .gitignore; do
  bak="$f.bak.perf02"
  if [ -f "$bak" ]; then
    cp "$bak" "$f"
    echo "✓ Restored $f from $bak"
    restored_any=1
  fi
done

if [ "$restored_any" = "0" ]; then
  echo "WARN: no .bak.perf02 backups found — attempting marker-based undo"
  python3 - <<'PY'
import re, sys
p = "cmd/gateway/main.go"
src = open(p, encoding="utf-8").read()
if "VSP_PATCH_PERF_02" not in src:
    print("Nothing to undo in main.go (marker absent)")
else:
    # Replace the multi-line PERF-02 block back to PERF-01 form
    new_block = (
        "\t// VSP_PATCH_PERF_01 — bumped 600 → 3000 to absorb dashboard burst (panel fan-out ~50 req/3s)\n"
        "\tr.Use(vspMW.NewUserRateLimiter(3000, time.Minute)) // per-user: 3000 req/min"
    )
    src = re.sub(
        r"\t// VSP_PATCH_PERF_02.*?// r\.Use\(vspMW\.NewUserRateLimiter\(3000, time\.Minute\)\) // per-user: 3000 req/min",
        new_block,
        src,
        count=1,
        flags=re.DOTALL,
    )
    open(p, "w", encoding="utf-8").write(src)
    print("✓ Reverted main.go via markers")

p = ".gitignore"
src = open(p, encoding="utf-8").read()
if "!patches/perf/" in src:
    src = src.replace("!patches/perf/\n!patches/perf/**\n", "")
    open(p, "w", encoding="utf-8").write(src)
    print("✓ Removed patches/perf/ whitelist from .gitignore")
PY
fi

echo ""
echo "✅ PERF-02 rolled back. Rebuild + redeploy gateway:"
echo "   bash scripts/build-gateway.sh"
echo "   sudo systemctl stop vsp-gateway && sleep 2"
echo "   sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway"
echo "   sudo systemctl start vsp-gateway"
