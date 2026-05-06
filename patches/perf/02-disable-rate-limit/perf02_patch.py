#!/usr/bin/env python3
"""
PERF-02 — Disable per-user rate limit on /api/v1/* group

Why: 3000/min is still insufficient because the browser bursts ~70 req in
<1s during dashboard boot (5 iframe panels × 5-8 GETs each, plus master
dashboard pollers). Rate limiter is per-user (1 admin = 1 bucket), so
even bumping to 10000/min only delays the inevitable. The right fix is
to drop the limiter for the authenticated app endpoints — defence is
already provided by:
  - JWT authMw (must auth first)
  - CSRFProtect (POST/PUT/DELETE)
  - tenant isolation
  - HTTPS + same-origin

We keep a stricter limit on /api/v1/auth/login to protect against brute
force — that's the one place rate limiting genuinely matters here.

Idempotent via marker: VSP_PATCH_PERF_02

Plus: fix .gitignore to whitelist patches/perf/ (was blocked by patches/* rule).

Usage: python3 perf02_patch.py /repo/root
"""
import sys
import os
import re

MARKER = "VSP_PATCH_PERF_02"

# Old line to comment out (after PERF-01)
RATE_LINE_OLD = (
    "\t// VSP_PATCH_PERF_01 — bumped 600 → 3000 to absorb dashboard burst (panel fan-out ~50 req/3s)\n"
    "\tr.Use(vspMW.NewUserRateLimiter(3000, time.Minute)) // per-user: 3000 req/min"
)

RATE_LINE_NEW = (
    "\t// VSP_PATCH_PERF_02 — per-user rate limit disabled on /api/v1/* group.\n"
    "\t// Reason: dashboard burst (~70 req in <1s during boot) exceeded 3000/min bucket\n"
    "\t// because limiter has no burst capacity. Defense remains via JWT authMw + CSRF +\n"
    "\t// tenant isolation. /api/v1/auth/login still rate-limited separately for\n"
    "\t// brute-force protection (see auth route registration).\n"
    "\t// To re-enable: uncomment the line below and adjust the limit.\n"
    "\t// r.Use(vspMW.NewUserRateLimiter(3000, time.Minute)) // per-user: 3000 req/min"
)

# Fallback for if PERF-01 marker absent — match original line directly
RATE_FALLBACK_OLD = "r.Use(vspMW.NewUserRateLimiter(3000, time.Minute)) // per-user: 3000 req/min"
RATE_FALLBACK_NEW = (
    "// VSP_PATCH_PERF_02 — rate limiter disabled (was 3000/min, insufficient for dashboard burst)\n"
    "\t// r.Use(vspMW.NewUserRateLimiter(3000, time.Minute)) // per-user: 3000 req/min"
)


def patch_main_go(path):
    if not os.path.exists(path):
        sys.stderr.write(f"ERROR: {path} not found\n")
        return 2

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    if MARKER in src:
        print(f"[PERF-02] main.go already patched (marker present). Skipping.")
        return 0

    if RATE_LINE_OLD in src:
        src2 = src.replace(RATE_LINE_OLD, RATE_LINE_NEW, 1)
        method = "PERF-01-aware replacement"
    elif RATE_FALLBACK_OLD in src:
        # Fallback if PERF-01 wasn't applied
        src2 = src.replace(RATE_FALLBACK_OLD, RATE_FALLBACK_NEW, 1)
        method = "fallback (PERF-01 marker absent)"
    else:
        sys.stderr.write("ERROR: rate limiter line not found\n")
        sys.stderr.write("Looked for: NewUserRateLimiter(3000, time.Minute)\n")
        return 3

    if src2 == src:
        sys.stderr.write("ERROR: no changes made\n")
        return 4

    tmp = path + ".tmp.perf02"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(src2)
    os.replace(tmp, path)

    print(f"[PERF-02] Patched main.go via {method} (rate limit disabled)")
    return 0


def patch_gitignore(repo_root):
    """Add patches/perf/ to whitelist so we can commit it."""
    path = os.path.join(repo_root, ".gitignore")
    if not os.path.exists(path):
        sys.stderr.write(f"WARN: {path} not found, skipping gitignore fix\n")
        return 0

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    if "!patches/perf/" in src:
        print(f"[PERF-02] .gitignore already whitelists patches/perf/ — skip")
        return 0

    # Find the F1 whitelist marker and add patches/perf/ right after !patches/findings/
    marker_line = "!patches/findings/"
    if marker_line not in src:
        sys.stderr.write(f"WARN: {marker_line} marker not found in .gitignore\n")
        sys.stderr.write("Appending whitelist block at EOF instead\n")
        addendum = "\n# PERF-02: whitelist patches/perf/\n!patches/perf/\n!patches/perf/**\n"
        src2 = src.rstrip() + "\n" + addendum
    else:
        # Insert !patches/perf/ block after !patches/findings/** (or after !patches/findings/)
        new_block = (
            "!patches/findings/\n"
            "!patches/findings/**\n"
            "!patches/perf/\n"
            "!patches/perf/**\n"
        )
        # Replace the existing findings whitelist with the expanded block
        if "!patches/findings/**" in src:
            src2 = src.replace(
                "!patches/findings/\n!patches/findings/**\n",
                new_block,
                1,
            )
        else:
            # Just findings/ without /**
            src2 = src.replace(
                "!patches/findings/\n",
                "!patches/findings/\n!patches/findings/**\n!patches/perf/\n!patches/perf/**\n",
                1,
            )

    if src2 == src:
        sys.stderr.write("WARN: gitignore unchanged after edit attempt\n")
        return 0

    tmp = path + ".tmp.perf02"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(src2)
    os.replace(tmp, path)

    print(f"[PERF-02] Patched .gitignore — patches/perf/ now whitelisted")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: perf02_patch.py /repo/root\n")
        sys.exit(1)

    repo = sys.argv[1]
    if not os.path.isdir(repo):
        sys.stderr.write(f"ERROR: {repo} is not a directory\n")
        sys.exit(2)

    rc1 = patch_main_go(os.path.join(repo, "cmd/gateway/main.go"))
    if rc1 != 0:
        sys.exit(rc1)

    rc2 = patch_gitignore(repo)
    sys.exit(rc2)
