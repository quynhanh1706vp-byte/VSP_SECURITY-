#!/usr/bin/env bash
# Block re-introduction of inline bootstrap blocks in panel HTML.
set -e

staged=$(git diff --cached --name-only --diff-filter=ACM | grep -E '^static/panels/.*\.html$' || true)
if [[ -z "$staged" ]]; then
  exit 0
fi

fail=0
for f in $staged; do
  if grep -q "VSP iframe token bootstrap v1" "$f" \
     && ! grep -q "vsp_iframe_bootstrap.js" "$f"; then
    echo "FAIL: $f has inline bootstrap v1 — use <script src=\"/static/js/vsp_iframe_bootstrap.js\"></script>"
    fail=1
  fi
done

if [[ $fail -eq 1 ]]; then
  echo ""
  echo "Fix: python3 scripts/consolidate_bootstrap.py"
  echo "See: SEC-005 in VSP_42_VanDe_vs_DevSecOps.docx"
  exit 1
fi
exit 0
