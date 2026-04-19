#!/usr/bin/env python3
"""Audit vsp_upgrade_v100.js for suspicious score/gate overrides."""
from __future__ import annotations
import pathlib
import re
import sys

FILE = pathlib.Path("static/vsp_upgrade_v100.js")

PATTERNS = [
    (r"\.textContent\s*=\s*['\"]?100['\"]?\b", "textContent = 100"),
    (r"\.textContent\s*=\s*['\"]PASS['\"]", "textContent = 'PASS' hardcoded"),
    (r"\.textContent\s*=\s*['\"]A['\"]", "textContent = 'A' grade hardcoded"),
    (r"\binnerHTML\s*=\s*[`'\"].*\b100\b.*[`'\"]", "innerHTML with 100"),
    (r"\bscore\s*=\s*100\b", "score = 100 assignment"),
    (r"\bgate\s*=\s*['\"]PASS['\"]", "gate = 'PASS' hardcoded"),
    (r"\bgrade\s*=\s*['\"]A['\"]", "grade = 'A' hardcoded"),
    (r"\|\|\s*100\b", "|| 100 fallback"),
    (r"\bscore\s*:\s*100\b", "score: 100 literal"),
    (r"\.data\.score\s*=", "overwriting response.data.score"),
    (r"data\.gate\s*=", "overwriting response.data.gate"),
]


def main():
    if not FILE.exists():
        print(f"error: {FILE} not found", file=sys.stderr)
        return 2

    lines = FILE.read_text(encoding="utf-8").splitlines()
    hits = []
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        for pat, label in PATTERNS:
            if re.search(pat, line):
                hits.append((lineno, label, stripped[:140]))
                break

    if not hits:
        print("No suspicious override patterns found.")
        return 0

    print(f"Found {len(hits)} suspicious lines in {FILE}:\n")
    for lineno, label, content in hits:
        print(f"  L{lineno:>5} [{label}]")
        print(f"         {content}")
        print()

    print("Each hit needs manual review:")
    print("  - Legitimate clamp (if score > 100 → 100): KEEP")
    print("  - Fake fallback (score || 100): CHANGE to (score ?? '—')")
    print("  - Hardcoded display: REMOVE, read from API response")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
