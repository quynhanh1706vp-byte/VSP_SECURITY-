#!/usr/bin/env python3
"""
mark-structured-safe.py — Add SEC-006 reviewed markers to STRUCTURED bucket sites.

These 12 sites use innerHTML with HTML tags but NO variable interpolation.
XSS risk = 0 because template is entirely fixed. However, innerHTML remains
a CSP concern, so we mark them as reviewed with a verifiable comment.

Before:
    card.innerHTML = `<div class="card-head">...</div>`;

After:
    // SEC-006 reviewed 2026-04-21: static HTML template, no data injection
    card.innerHTML = `<div class="card-head">...</div>`;

This gives:
  - Evidence of review (grep'able)
  - Future reviewers know not to worry
  - CI can enforce: new innerHTML requires either migration OR this marker
"""

import csv
import sys
from pathlib import Path
from datetime import date

DRY_RUN = '--apply' not in sys.argv
MARKER = f'// SEC-006 reviewed {date.today().isoformat()}: static HTML template, no data injection'


def load_sites():
    csv_path = Path('docs/sprint4/innerhtml-high-classified.csv')
    with csv_path.open() as f:
        return [
            {'file': r['file'], 'line': int(r['line'])}
            for r in csv.DictReader(f)
            if r['bucket'] == 'STRUCTURED'
        ]


def process_file(filepath, lines_to_mark):
    with open(filepath) as f:
        lines = f.readlines()

    # Sort desc so inserting doesn't shift later line numbers
    lines_to_mark = sorted(lines_to_mark, reverse=True)
    changes = 0

    for line_num in lines_to_mark:
        idx = line_num - 1
        if idx >= len(lines) or idx < 0:
            continue

        target = lines[idx]

        # Skip if already marked (idempotent)
        if idx > 0 and 'SEC-006 reviewed' in lines[idx - 1]:
            print(f"  L{line_num}: already marked, skipping")
            continue

        # Detect indentation from target line
        indent = ''
        for c in target:
            if c in ' \t':
                indent += c
            else:
                break

        marker_line = f"{indent}{MARKER}\n"
        lines.insert(idx, marker_line)
        changes += 1
        print(f"  L{line_num}: marked  →  {target.strip()[:80]}")

    if changes and not DRY_RUN:
        with open(filepath, 'w') as f:
            f.writelines(lines)

    return changes


def main():
    sites = load_sites()
    print(f"Loaded {len(sites)} STRUCTURED sites\n")

    by_file = {}
    for s in sites:
        by_file.setdefault(s['file'], []).append(s['line'])

    total = 0
    for filepath, lines in sorted(by_file.items()):
        print(f"{'DRY ' if DRY_RUN else ''}→ {filepath}:")
        changes = process_file(filepath, lines)
        total += changes
        print()

    print(f"{'DRY RUN — ' if DRY_RUN else ''}Total markers added: {total}")
    if DRY_RUN:
        print("Run with --apply to write changes.")


if __name__ == '__main__':
    main()
