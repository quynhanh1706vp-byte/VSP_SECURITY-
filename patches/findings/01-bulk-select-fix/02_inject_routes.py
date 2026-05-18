#!/usr/bin/env python3
"""
F1 Backend Patcher — register routes in cmd/gateway/main.go (chi router).

Strategy:
  1. Copy bulk_findings.go into cmd/gateway/ (idempotent — skip if identical).
  2. Inject 2 route lines into main.go right after a known anchor:
       `r.With(ca.Middleware("findings-summary", ...)).Get("/api/v1/vsp/findings/summary", ...)`
     This anchor is INSIDE the authenticated /api/v1 route group (per the
     repo, it sits between r.Use(NewUserRateLimiter) and the group's `})`),
     so the routes inherit auth + per-user rate limiting automatically.
  3. Wrap injected lines in marker comments so re-run is safe.

Idempotent: skip if marker found.
"""
import sys
import os
import shutil
import re

PATCH_ID = "F1"
MARK_BEGIN = "// VSP_PATCH_F1_ROUTES_BEGIN"
MARK_END = "// VSP_PATCH_F1_ROUTES_END"

# Anchor: a line we know exists in main.go (from grep output line 879).
# We insert AFTER this line, INSIDE the same indent block.
ANCHOR_RE = re.compile(
    r'^(?P<indent>[ \t]+)r\.With\([^\n]*\)\.Get\("/api/v1/vsp/findings/summary"[^\n]*\)\s*\n',
    re.MULTILINE,
)

INJECT_TEMPLATE = (
    "{INDENT}{MARK_BEGIN}\n"
    "{INDENT}r.Post(\"/api/v1/vulns/bulk\",      handleVulnsBulk)\n"
    "{INDENT}r.Post(\"/api/v1/vulns/bulk/undo\", handleVulnsBulkUndo)\n"
    "{INDENT}{MARK_END}\n"
)


def install_go_file(src_go, dst_dir):
    """Copy bulk_findings.go to cmd/gateway/. Idempotent."""
    if not os.path.exists(src_go):
        sys.stderr.write(f"ERROR: source {src_go} not found\n")
        return 2
    if not os.path.isdir(dst_dir):
        sys.stderr.write(f"ERROR: dst dir {dst_dir} not found\n")
        return 2

    dst = os.path.join(dst_dir, "bulk_findings.go")
    if os.path.exists(dst):
        with open(src_go, "rb") as a, open(dst, "rb") as b:
            if a.read() == b.read():
                print(f"[F1] {dst} already up-to-date")
                return 0
        bak = dst + ".bak.f1"
        if not os.path.exists(bak):
            shutil.copy2(dst, bak)
            print(f"[F1] Existing {dst} backed up to {bak}")
    shutil.copy2(src_go, dst)
    print(f"[F1] Installed: {dst}")
    return 0


def patch_main_go(main_path):
    """Inject 2 r.Post lines after the findings-summary anchor."""
    if not os.path.exists(main_path):
        sys.stderr.write(f"ERROR: {main_path} not found\n")
        return 2

    with open(main_path, "r", encoding="utf-8") as f:
        src = f.read()

    if MARK_BEGIN in src:
        print(f"[F1] {main_path} already has F1 routes (marker found). Skipping.")
        return 0

    m = ANCHOR_RE.search(src)
    if not m:
        sys.stderr.write(
            "ERROR: anchor not found in main.go\n"
            "       expected: r.With(...).Get(\"/api/v1/vsp/findings/summary\", ...)\n"
        )
        return 3

    indent = m.group("indent")
    inject = INJECT_TEMPLATE.format(
        INDENT=indent, MARK_BEGIN=MARK_BEGIN, MARK_END=MARK_END
    )

    # Insert the new block right after the matched line
    insertion_pos = m.end()
    new_src = src[:insertion_pos] + inject + src[insertion_pos:]

    # Atomic write via temp file
    tmp = main_path + ".tmp.f1"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(new_src)
    os.replace(tmp, main_path)

    added = new_src.count("\n") - src.count("\n")
    print(f"[F1] Patched {main_path} (+{added} lines, anchor at offset {m.start()})")
    return 0


def main():
    if len(sys.argv) != 4:
        sys.stderr.write(
            "Usage: 02_inject_routes.py <main.go-path> <gateway-dir> <bulk_findings.go-path>\n"
        )
        return 1

    main_path, gw_dir, src_go = sys.argv[1], sys.argv[2], sys.argv[3]

    rc = install_go_file(src_go, gw_dir)
    if rc != 0:
        return rc

    rc = patch_main_go(main_path)
    if rc != 0:
        return rc

    return 0


if __name__ == "__main__":
    sys.exit(main())
