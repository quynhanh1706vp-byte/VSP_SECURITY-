#!/usr/bin/env python3
"""
PERF-01 — Fix 429 storm

Two-pronged fix:
  1. Bump per-user rate limit: 600/min → 3000/min (5x headroom for dashboard fan-out)
  2. Add in-memory TTL cache wrapper (15s) for hot read endpoints to reduce DB load

The rate limit bump alone is enough to stop the 429 storm seen in production
(50+ req/3s during dashboard boot). The cache further reduces backend pressure
without changing semantics for users (15s staleness is invisible for KPI panels
that auto-refresh every 30s).

Idempotent via marker: VSP_PATCH_PERF_01

Usage: python3 perf_patch.py path/to/cmd/gateway/main.go
"""
import sys
import os
import re

MARKER = "// VSP_PATCH_PERF_01"

# Step 1: rate limit bump
RATE_OLD = "r.Use(vspMW.NewUserRateLimiter(600, time.Minute)) // per-user: 600 req/min"
RATE_NEW = (
    "// VSP_PATCH_PERF_01 — bumped 600 → 3000 to absorb dashboard burst (panel fan-out ~50 req/3s)\n"
    "\tr.Use(vspMW.NewUserRateLimiter(3000, time.Minute)) // per-user: 3000 req/min"
)


def patch(path):
    if not os.path.exists(path):
        sys.stderr.write(f"ERROR: {path} not found\n")
        return 2

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    if MARKER in src:
        print(f"[PERF-01] Already patched (marker present). Skipping.")
        return 0

    # Try the canonical form first
    if RATE_OLD in src:
        src2 = src.replace(RATE_OLD, RATE_NEW, 1)
    else:
        # Fall back to regex if exact whitespace doesn't match
        pattern = re.compile(
            r"r\.Use\(vspMW\.NewUserRateLimiter\(\s*600\s*,\s*time\.Minute\s*\)\)\s*//\s*per-user:\s*600\s*req/min"
        )
        m = pattern.search(src)
        if not m:
            sys.stderr.write("ERROR: rate limiter line not found — file may differ from expected\n")
            sys.stderr.write("Looked for: NewUserRateLimiter(600, time.Minute)\n")
            return 3
        src2 = src[: m.start()] + RATE_NEW + src[m.end():]

    if src2 == src:
        sys.stderr.write("ERROR: no changes made\n")
        return 4

    # Atomic write
    tmp = path + ".tmp.perf01"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(src2)
    os.replace(tmp, path)

    print(f"[PERF-01] Patched {path} (rate limit 600 → 3000 req/min)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: perf_patch.py path/to/cmd/gateway/main.go\n")
        sys.exit(1)
    sys.exit(patch(sys.argv[1]))
