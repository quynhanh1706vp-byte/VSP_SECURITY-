#!/usr/bin/env python3
"""
migrate-text-innerhtml.py — Auto-fix TEXT bucket (36 sites).

For `el.innerHTML = \`plain text with ${interp}\`` patterns:
  → `el.textContent = \`plain text with ${interp}\``

This is safe because:
  - Template literal evaluation happens BEFORE textContent assignment
  - textContent cannot execute scripts, render HTML, or trigger event handlers
  - Visual result is identical when source has no HTML tags

Dry-run by default. Pass --apply to write changes.
"""

import re
import sys
import csv
from pathlib import Path

DRY_RUN = '--apply' not in sys.argv


def load_text_sites():
    """Load TEXT bucket sites from classified CSV."""
    csv_path = Path('docs/sprint4/innerhtml-high-classified.csv')
    sites = []
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['bucket'] == 'TEXT':
                sites.append({
                    'file': row['file'],
                    'line': int(row['line']),
                })
    return sites


def migrate_file(filepath, lines_to_fix):
    """Replace `.innerHTML = \`...\`` with `.textContent = \`...\`` at given lines."""
    with open(filepath) as f:
        content = f.read()

    lines = content.split('\n')
    changes = []

    for line_num in lines_to_fix:
        idx = line_num - 1
        if idx >= len(lines):
            continue

        original = lines[idx]
        # Replace `.innerHTML = \`` with `.textContent = \``
        new_line = re.sub(
            r'([\w.$]+(?:\([^)]*\)|\[[^\]]+\]|\.\w+)*)\.innerHTML(\s*=\s*`)',
            r'\1.textContent\2',
            original,
            count=1
        )

        if new_line != original:
            changes.append({
                'line': line_num,
                'before': original.strip()[:100],
                'after': new_line.strip()[:100],
            })
            lines[idx] = new_line

    if changes and not DRY_RUN:
        with open(filepath, 'w') as f:
            f.write('\n'.join(lines))

    return changes


def main():
    sites = load_text_sites()
    print(f"Loaded {len(sites)} TEXT sites from classified CSV\n")

    # Group by file
    by_file = {}
    for s in sites:
        by_file.setdefault(s['file'], []).append(s['line'])

    total_changes = 0
    for filepath, lines in sorted(by_file.items()):
        changes = migrate_file(filepath, lines)
        if not changes:
            print(f"⚠ {filepath}: no changes applied (regex didn't match)")
            continue
        total_changes += len(changes)
        print(f"{'DRY ' if DRY_RUN else ''}✓ {filepath}: {len(changes)} fix(es)")
        for c in changes[:2]:
            print(f"    L{c['line']}: {c['before'][:80]}")
            print(f"         → {c['after'][:80]}")
        if len(changes) > 2:
            print(f"    ... +{len(changes)-2} more")

    print(f"\n{'DRY RUN — ' if DRY_RUN else ''}Total: {total_changes} fixes across {len(by_file)} files")
    if DRY_RUN:
        print("Run with --apply to write changes.")


if __name__ == '__main__':
    main()
