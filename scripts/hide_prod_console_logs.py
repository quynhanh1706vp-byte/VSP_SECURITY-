#!/usr/bin/env python3
"""
Wrap production-sensitive console.log calls in VSP_DEBUG flag.

Before:
    console.log('[VSP] PATCH v3.0 loaded ...');
After:
    if(window.VSP_DEBUG)console.log('[VSP] PATCH v3.0 loaded ...');

Usage:
    python3 scripts/hide_prod_console_logs.py --dry-run
    python3 scripts/hide_prod_console_logs.py
"""
from __future__ import annotations
import argparse
import pathlib
import re
import sys

TARGETS = [
    pathlib.Path("static/vsp_upgrade_v100.js"),
    pathlib.Path("static/panels/p4_compliance.html"),
]

SENSITIVE = [
    "PATCH v", "override", "FINAL", "DEFINITIVE", "LAST_OVERRIDE",
    "Upgrade", "mock for", "installed",
]

LOG_RE = re.compile(
    r'^(?P<indent>[ \t]*)console\.log\((?P<args>.+?)\);[ \t]*$',
    re.MULTILINE,
)


def is_sensitive(args: str) -> bool:
    return any(kw in args for kw in SENSITIVE)


def process(path: pathlib.Path, dry_run: bool):
    text = path.read_text(encoding="utf-8")
    wrapped = [0]

    def replace(m):
        args = m.group("args")
        indent = m.group("indent")
        if not is_sensitive(args):
            return m.group(0)
        if "VSP_DEBUG" in m.group(0):
            return m.group(0)  # already wrapped
        wrapped[0] += 1
        return f"{indent}if(window.VSP_DEBUG)console.log({args});"

    new_text = LOG_RE.sub(replace, text)
    total = len(list(LOG_RE.finditer(text)))
    if not dry_run and wrapped[0] > 0:
        path.write_text(new_text, encoding="utf-8")
    return total, wrapped[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    total = wrapped = 0
    for p in TARGETS:
        if not p.exists():
            print(f"skip (not found): {p}", file=sys.stderr)
            continue
        m, w = process(p, args.dry_run)
        total += m
        wrapped += w
        print(f"{p}: {m} console.log total, {w} wrapped")

    print(f"\nSummary: {wrapped}/{total} sensitive console.log wrapped")
    if args.dry_run:
        print("(dry-run — no files modified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
