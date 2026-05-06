#!/usr/bin/env python3
"""
PERF-03 — Disable global IP rate limiter

Root cause of the 429 storm: cmd/gateway/main.go line 444+465 set up a
GLOBAL per-IP rate limiter (600 req/min) that runs BEFORE the per-user
limiter we already disabled in PERF-02.

  Line 444: rl := vspMW.NewRateLimiter(600, time.Minute)  ← creates it
  Line 465: r.Use(rl.Middleware)                          ← applies to ALL routes

Browser bursts ~70 req/s during dashboard boot. Combined with the
chimw.RealIP middleware (line 451) which sets r.RemoteAddr from
X-Forwarded-For (forwarded by nginx), every request from one browser
hits the same bucket, exhausting 600 in ~9 seconds.

Defense in depth without this limiter:
  - JWT authMw (line ~474+ on /api/v1 group)
  - CSRFProtect (line 449)
  - 4MB body limit (line 459-463)
  - 60s timeout (line 458)
  - tenant isolation in handlers
  - nginx layer (could add nginx rate limit upstream if needed)

Idempotent via marker: VSP_PATCH_PERF_03

Usage: python3 perf03_patch.py /repo/root/cmd/gateway/main.go
"""
import sys
import os
import re

MARKER = "VSP_PATCH_PERF_03"

# Step A: comment out the rl initialization
RL_INIT_OLD = "\trl := vspMW.NewRateLimiter(600, time.Minute)"
RL_INIT_NEW = (
    "\t// VSP_PATCH_PERF_03 — global per-IP rate limiter disabled.\n"
    "\t// Reason: dashboard burst of ~70 req/s exhausted 600/min bucket within\n"
    "\t// seconds, causing prolonged 429 storms. Defense remains via JWT auth,\n"
    "\t// CSRF protect, 4MB body limit, 60s timeout, and nginx layer.\n"
    "\t// To re-enable, uncomment both this and r.Use(rl.Middleware) below.\n"
    "\t_ = vspMW.NewRateLimiter // keep package imported\n"
    "\t// rl := vspMW.NewRateLimiter(600, time.Minute)"
)

# Step B: comment out the r.Use(rl.Middleware) call
RL_USE_OLD = "\tr.Use(rl.Middleware)"
RL_USE_NEW = "\t// VSP_PATCH_PERF_03 — disabled: r.Use(rl.Middleware)"


def patch(path):
    if not os.path.exists(path):
        sys.stderr.write(f"ERROR: {path} not found\n")
        return 2

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    if MARKER in src:
        print(f"[PERF-03] Already patched (marker present). Skipping.")
        return 0

    # Step A
    if RL_INIT_OLD not in src:
        sys.stderr.write(f"ERROR: rl init line not found\n")
        sys.stderr.write(f"Looked for: {RL_INIT_OLD!r}\n")
        return 3
    src2 = src.replace(RL_INIT_OLD, RL_INIT_NEW, 1)

    # Step B
    if RL_USE_OLD not in src2:
        sys.stderr.write(f"ERROR: r.Use(rl.Middleware) line not found\n")
        return 3
    src3 = src2.replace(RL_USE_OLD, RL_USE_NEW, 1)

    if src3 == src:
        sys.stderr.write("ERROR: no changes made\n")
        return 4

    tmp = path + ".tmp.perf03"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(src3)
    os.replace(tmp, path)

    print(f"[PERF-03] Patched main.go — global IP rate limiter disabled (2 sites)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: perf03_patch.py path/to/cmd/gateway/main.go\n")
        sys.exit(1)
    sys.exit(patch(sys.argv[1]))
