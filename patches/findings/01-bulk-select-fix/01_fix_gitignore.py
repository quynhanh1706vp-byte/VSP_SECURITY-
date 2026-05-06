#!/usr/bin/env python3
"""
01_fix_gitignore.py — surgical .gitignore edit for Sprint 1 F1-F8.

Problem with the current .gitignore:
  Line "patches/" excludes the WHOLE patches/ tree. Per git's gitignore
  semantics, a re-include rule (!patches/findings/) cannot bring back
  files under an excluded parent directory.

Fix:
  1. Change `patches/` → `patches/*` (still excludes everything by default,
     BUT now allows re-including specific subdirectories).
  2. Append F1 whitelist block (only if marker not present).

Idempotent: detects marker + transformed line.
"""
import sys
import os
import re
import shutil

MARKER = "# === Sprint 1 Findings Pro — F1-F8 whitelist (added by patch) ==="

WHITELIST_BLOCK = """
# === Sprint 1 Findings Pro — F1-F8 whitelist (added by patch) ===
# Override the broad ignores for production-tracked Sprint 1 deliverables.
# Note: the original `patches/` rule above was changed to `patches/*` so
# that re-include rules below can take effect.

# Un-ignore the entire patches/findings/ subtree
!patches/findings/
!patches/findings/**

# Each Sprint 1 F* feature script — explicit per-file allow
!static/js/vsp_bulk_f1.js
# (future entries: !static/js/vsp_filter_f2.js, vsp_cvss_sort_f3.js, ...)

# Defensive: keep .bak / generated artifacts ignored inside patches/
patches/findings/**/*.bak
patches/findings/**/*.bak.*
patches/findings/**/*.tmp
"""


def fix(path):
    if not os.path.exists(path):
        sys.stderr.write(f"ERROR: {path} not found\n")
        return 2

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    # Backup once
    bak = path + ".bak.f1"
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
        print(f"[F1] Backup: {bak}")

    changed = False

    # Step 1: Replace `patches/` with `patches/*` if not done already
    # Match exact line "patches/" (with optional trailing whitespace)
    new_src, n = re.subn(
        r"^patches/\s*$",
        "patches/*",
        src,
        count=1,
        flags=re.MULTILINE,
    )
    if n == 1:
        print("[F1] Transformed `patches/` → `patches/*` for re-include support")
        src = new_src
        changed = True
    elif "patches/*" in src:
        print("[F1] `patches/*` already in place")
    else:
        print("[F1] WARN: `patches/` line not found (may already be patched manually)")

    # Step 2: Append whitelist block if not present
    if MARKER in src:
        print("[F1] Whitelist block already present")
    else:
        if not src.endswith("\n"):
            src += "\n"
        src += WHITELIST_BLOCK
        print("[F1] Appended whitelist block")
        changed = True

    if changed:
        tmp = path + ".tmp.f1"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(src)
        os.replace(tmp, path)
        print(f"[F1] Wrote {path}")
    else:
        print("[F1] No changes needed")

    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: 01_fix_gitignore.py <gitignore-path>\n")
        sys.exit(1)
    sys.exit(fix(sys.argv[1]))
