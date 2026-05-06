#!/usr/bin/env python3
"""
F1 Bulk-Select Patcher v2 — Strategy C+ (additive standalone JS)
================================================================
Does ONLY two things:
  1. Copy vsp_bulk_f1.js to static/js/
  2. Inject `<script src="/static/js/vsp_bulk_f1.js"></script>` before </body>
     in static/panels/vuln_mgmt.html, wrapped in marker comments.

No core script modification. No conflict with existing inline blocks.

Usage:  python3 frontend.py <path-to-vuln_mgmt.html> <path-to-static-js-dir> <path-to-vsp_bulk_f1.js>
"""
import sys
import os
import shutil

PATCH_ID = "F1"
MARKER_START = f"<!-- VSP_F1_SCRIPT_START -->"
MARKER_END = f"<!-- VSP_F1_SCRIPT_END -->"

SCRIPT_TAG_BLOCK = f"""{MARKER_START}
<!-- F1 Bulk Select Hub — additive feature (Sprint 1, patch 1/8) -->
<script src="/static/js/vsp_bulk_f1.js" defer></script>
{MARKER_END}
"""


def patch_html(html_path):
    if not os.path.exists(html_path):
        sys.stderr.write(f"ERROR: {html_path} not found\n")
        return 2

    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    original = content

    if MARKER_START in content:
        print(f"[F1] HTML already patched (found {MARKER_START}). Skipping.")
        return 0

    if "</body>" not in content:
        sys.stderr.write("ERROR: </body> anchor missing in HTML\n")
        return 3

    # Insert before </body>
    content = content.replace("</body>", SCRIPT_TAG_BLOCK + "</body>", 1)

    if content == original:
        sys.stderr.write("ERROR: HTML unchanged after replace\n")
        return 4

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[F1] HTML patched: {html_path} (+{content.count(chr(10)) - original.count(chr(10))} lines)")
    return 0


def install_js(js_dir, src_js):
    if not os.path.exists(src_js):
        sys.stderr.write(f"ERROR: source JS {src_js} not found\n")
        return 2

    os.makedirs(js_dir, exist_ok=True)
    dst = os.path.join(js_dir, "vsp_bulk_f1.js")

    if os.path.exists(dst):
        # If checksum matches, no-op
        with open(src_js, "rb") as a, open(dst, "rb") as b:
            if a.read() == b.read():
                print(f"[F1] JS already installed at {dst} (identical content)")
                return 0
        # Different content — back up old
        bak = dst + ".bak.f1"
        if not os.path.exists(bak):
            shutil.copy2(dst, bak)
            print(f"[F1] Existing JS backed up to {bak}")

    shutil.copy2(src_js, dst)
    print(f"[F1] JS installed: {dst}")
    return 0


def main():
    if len(sys.argv) != 4:
        sys.stderr.write(
            "Usage: frontend.py <html-path> <js-dir> <src-js>\n"
            "  e.g.  frontend.py static/panels/vuln_mgmt.html static/js patches/findings/01-bulk-select/vsp_bulk_f1.js\n"
        )
        return 1

    html, js_dir, src_js = sys.argv[1], sys.argv[2], sys.argv[3]

    rc = install_js(js_dir, src_js)
    if rc != 0:
        return rc

    rc = patch_html(html)
    if rc != 0:
        return rc

    return 0


if __name__ == "__main__":
    sys.exit(main())
