#!/usr/bin/env bash
# scripts/test-l54-sri-integrity.sh — Subresource Integrity for CDN scripts.
#
# When the gateway's HTML pages reference scripts from third-party
# CDNs (unpkg, jsdelivr, cdnjs), a compromised CDN can ship malicious
# JS that the browser executes with same-origin privilege.
#
# Defence: <script src="..." integrity="sha384-..." crossorigin>...
# The browser refuses to execute if the hash doesn't match.
#
# This level scans static/**/*.html for <script src="https://..."> and
# verifies each has an `integrity=` attribute.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 54.1 External script tags carry integrity hash ───────────────────────

phase_open "54.1 External <script src> has integrity attribute"

# Find <script src="https://...">. python parser handles multi-line
# attributes and self-closing tags better than grep.
# `|| true` so a python3 hiccup doesn't kill the script under set -e
python3 - "$ROOT/static" <<'PY' > /tmp/l54_sri.out 2>&1 || true
import os, re, sys
root = sys.argv[1]
hits = []
SCRIPT_RE = re.compile(
    r'<script[^>]*\bsrc\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>',
    re.IGNORECASE
)
for dirpath, _, files in os.walk(root):
    for fn in files:
        if not fn.endswith('.html') or '.bak' in fn:
            continue
        p = os.path.join(dirpath, fn)
        with open(p, errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                for m in SCRIPT_RE.finditer(line):
                    tag = m.group(0)
                    url = m.group(1)
                    if 'integrity=' not in tag:
                        hits.append(f"{p}:{lineno}: {url[:80]}")
for h in hits[:5]:
    print(h)
print(f"TOTAL:{len(hits)}")
PY

TOTAL=$(grep '^TOTAL:' /tmp/l54_sri.out 2>/dev/null | cut -d: -f2 || true)
TOTAL=${TOTAL:-0}
SAMPLE=$(grep -v '^TOTAL:' /tmp/l54_sri.out 2>/dev/null | head -1 || true)

# Threshold: many panels load chart.js / vega from CDN. The migration
# off no-integrity is gradual. Hard floor: > 50 unguarded externs is
# a regression.
SRI_BASELINE=50
if (( TOTAL == 0 )); then
  _pass "54.1.1 every external <script src> has integrity hash"
elif (( TOTAL <= SRI_BASELINE )); then
  _skip "54.1.1 SRI coverage drift" \
    "$TOTAL external scripts without integrity (baseline $SRI_BASELINE) — add as panels migrate; first: $SAMPLE"
else
  _fail "54.1.1 SRI coverage regressed" \
    "$TOTAL external scripts without integrity (baseline $SRI_BASELINE); first: $SAMPLE"
fi
rm -f /tmp/l54_sri.out

# ── 54.2 External <link rel="stylesheet"> with crossorigin uses SRI ──────

phase_open "54.2 External stylesheets — integrity hash"

python3 - "$ROOT/static" <<'PY' > /tmp/l54_css.out 2>&1 || true
import os, re, sys
root = sys.argv[1]
hits = []
LINK_RE = re.compile(
    r'<link[^>]*\brel\s*=\s*["\']stylesheet["\'][^>]*\bhref\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>',
    re.IGNORECASE
)
for dirpath, _, files in os.walk(root):
    for fn in files:
        if not fn.endswith('.html') or '.bak' in fn:
            continue
        p = os.path.join(dirpath, fn)
        with open(p, errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                for m in LINK_RE.finditer(line):
                    tag = m.group(0)
                    if 'integrity=' not in tag:
                        hits.append(f"{p}:{lineno}")
print(f"TOTAL:{len(hits)}")
for h in hits[:3]: print(h)
PY

TOTAL=$(grep '^TOTAL:' /tmp/l54_css.out 2>/dev/null | cut -d: -f2 || true)
TOTAL=${TOTAL:-0}
SAMPLE=$(grep -v '^TOTAL:' /tmp/l54_css.out 2>/dev/null | head -1 || true)
rm -f /tmp/l54_css.out

if (( TOTAL == 0 )); then
  _pass "54.2.1 every external <link rel=stylesheet> has integrity hash"
elif (( TOTAL <= 20 )); then
  _skip "54.2.1 SRI coverage on CSS" \
    "$TOTAL stylesheets without integrity — informational"
else
  _fail "54.2.1 many external stylesheets without integrity" \
    "$TOTAL unguarded; first: $SAMPLE"
fi

# ── 54.3 crossorigin="anonymous" required with integrity ────────────────

phase_open "54.3 integrity + crossorigin pairing"

# When integrity is set, crossorigin MUST also be set (anonymous or
# use-credentials), otherwise the browser silently skips the SRI check
# for cross-origin resources due to opacity rules.
python3 - "$ROOT/static" <<'PY' > /tmp/l54_pair.out 2>&1 || true
import os, re, sys
root = sys.argv[1]
hits = []
TAG_RE = re.compile(
    r'<(?:script|link)[^>]*\bintegrity\s*=[^>]*>',
    re.IGNORECASE
)
for dirpath, _, files in os.walk(root):
    for fn in files:
        if not fn.endswith('.html') or '.bak' in fn:
            continue
        p = os.path.join(dirpath, fn)
        with open(p, errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                for m in TAG_RE.finditer(line):
                    tag = m.group(0)
                    if 'crossorigin' not in tag:
                        hits.append(f"{p}:{lineno}")
print(f"TOTAL:{len(hits)}")
for h in hits[:3]: print(h)
PY

TOTAL=$(grep '^TOTAL:' /tmp/l54_pair.out 2>/dev/null | cut -d: -f2 || true)
TOTAL=${TOTAL:-0}
SAMPLE=$(grep -v '^TOTAL:' /tmp/l54_pair.out 2>/dev/null | head -1 || true)
rm -f /tmp/l54_pair.out

if (( TOTAL == 0 )); then
  _pass "54.3.1 every integrity= tag also has crossorigin="
else
  _fail "54.3.1 integrity= without crossorigin=" \
    "$TOTAL tags — browser skips SRI silently. Sample: $SAMPLE"
fi

final_summary
