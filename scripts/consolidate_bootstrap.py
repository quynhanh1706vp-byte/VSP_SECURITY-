#!/usr/bin/env python3
"""
Consolidate VSP iframe bootstrap — v1 -> v2.

Usage:
  python3 scripts/consolidate_bootstrap.py --dry-run     # preview
  python3 scripts/consolidate_bootstrap.py               # apply

Run from repo root: /home/test/Data/GOLANG_VSP
"""
from __future__ import annotations
import argparse
import pathlib
import re
import sys

PANEL_DIR = pathlib.Path("static/panels")
BOOTSTRAP_RE = re.compile(
    r'<script>\s*\n?\s*/\*\s*VSP iframe token bootstrap v1.*?\*/\s*'
    r'\(function\s*\(\)\s*\{.*?\}\)\(\);\s*\n?\s*</script>\s*\n?',
    re.DOTALL,
)
REPLACEMENT = '<script src="/static/js/vsp_iframe_bootstrap.js"></script>\n'


def process(path: pathlib.Path, dry_run: bool) -> str:
    text = path.read_text(encoding="utf-8")
    if 'vsp_iframe_bootstrap.js' in text:
        return 'already-v2'
    new_text, n = BOOTSTRAP_RE.subn(REPLACEMENT, text, count=1)
    if n == 0:
        return 'no-bootstrap'
    if not dry_run:
        path.write_text(new_text, encoding="utf-8")
    return 'patched'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--panel-dir", default=str(PANEL_DIR))
    args = ap.parse_args()

    panel_dir = pathlib.Path(args.panel_dir)
    if not panel_dir.is_dir():
        print(f"error: {panel_dir} not found (run from repo root)", file=sys.stderr)
        return 2

    counters = {'patched': 0, 'already-v2': 0, 'no-bootstrap': 0}
    for p in sorted(panel_dir.glob("*.html")):
        status = process(p, args.dry_run)
        counters[status] += 1
        marker = {'patched': 'OK', 'already-v2': '==', 'no-bootstrap': '..'}[status]
        print(f"{marker} {status:14} {p}")

    print("\nSummary:")
    for k, v in counters.items():
        print(f"  {k:14} {v}")
    if args.dry_run:
        print("\n(dry-run — no files were modified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
