#!/usr/bin/env python3
"""Make the sidebar gate widget dynamic (fix hardcoded 'GATE FAIL')."""
import pathlib
import re
import sys

PATH = pathlib.Path("static/index.html")
if not PATH.exists():
    print(f"error: {PATH} not found", file=sys.stderr)
    sys.exit(1)

text = PATH.read_text(encoding="utf-8")

text, n1 = re.subn(
    r'<span class="gate-icon">\u2717</span>',
    '<span class="gate-icon" id="d-gate-icon">\u2014</span>',
    text,
)
text, n2 = re.subn(
    r'<span class="gate-label">GATE FAIL</span>',
    '<span class="gate-label" id="d-gate-label">GATE \u2014</span>',
    text,
)

if n1 + n2 == 0:
    print("WARN: no matches (already patched?)")
    sys.exit(0)

PATH.write_text(text, encoding="utf-8")
print(f"OK: patched {n1} icon + {n2} label")
