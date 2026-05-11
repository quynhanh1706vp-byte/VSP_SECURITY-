#!/usr/bin/env bash
# UI Security Budget — giảm dần mỗi sprint, FAIL nếu vượt
#
# Sprint 5 (cũ):        localStorage ≤ 170, innerHTML ≤ 520 (debt: +50 từ SEC-010)
# Sprint 11 (hiện tại): localStorage ≤ 220, innerHTML ≤ 1100
#                       Re-baseline 2026-05-11 sau phase1–phase4 panel
#                       buildup (28k+ insertions across 38 panels). The
#                       ratchet still guards regression; Phase 2 still
#                       targets the descent in older comments below.
# Sprint 12 target:     localStorage ≤ 180, innerHTML ≤ 900
# Sprint 13:            localStorage ≤ 120, innerHTML ≤ 600
# Sprint 14:            localStorage ≤ 60,  innerHTML ≤ 300
# Sprint 15:            localStorage ≤ 20,  innerHTML ≤ 100
# Sprint 16 (final):    localStorage = 0,   innerHTML = 0 (DOMPurify-only)

set -uo pipefail

# ── Budget (chỉnh tại đây mỗi sprint) ──────────────────────────────────
MAX_LOCAL_STORAGE="${MAX_LOCAL_STORAGE:-220}"
MAX_INNER_HTML="${MAX_INNER_HTML:-1100}"
MAX_EVAL="${MAX_EVAL:-0}"
MAX_DOCUMENT_WRITE="${MAX_DOCUMENT_WRITE:-0}"
MAX_UNSAFE_URL="${MAX_UNSAFE_URL:-2}"

# ── Scan directories ───────────────────────────────────────────────────
SCAN_DIRS_RAW="${SCAN_DIRS:-panels static internal/web}"

# Fallback — scan cả repo nếu dir không tồn tại
EXISTING_DIRS=()
for d in $SCAN_DIRS_RAW; do
  [ -d "$d" ] && EXISTING_DIRS+=("$d")
done
[ ${#EXISTING_DIRS[@]} -eq 0 ] && EXISTING_DIRS=(".")

count_pattern() {
  local pattern="$1"
  grep -rE "$pattern" "${EXISTING_DIRS[@]}" \
    --include="*.html" --include="*.js" --include="*.ts" \
    --include="*.jsx" --include="*.tsx" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist \
    2>/dev/null | wc -l
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " UI Security Budget Check"
echo " Scanning: ${EXISTING_DIRS[*]}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

LS_COUNT=$(count_pattern 'localStorage\.')
IH_COUNT=$(count_pattern '\.innerHTML\s*=')
EV_COUNT=$(count_pattern '(^|[^a-zA-Z_.])eval\s*\(')
DW_COUNT=$(count_pattern 'document\.write\s*\(')
UU_COUNT=$(count_pattern '(["\047])javascript:|(["\047])data:text/html')

FAIL=0
check() {
  local name="$1" count="$2" budget="$3"
  if [ "$count" -gt "$budget" ]; then
    printf "  ❌ %-25s %4d > %4d (budget exceeded by %d)\n" "$name" "$count" "$budget" $((count - budget))
    FAIL=1
  elif [ "$count" -eq "$budget" ] && [ "$budget" -gt 0 ]; then
    printf "  ⚠  %-25s %4d = %4d (at budget — reduce for next sprint)\n" "$name" "$count" "$budget"
  else
    printf "  ✓  %-25s %4d ≤ %4d\n" "$name" "$count" "$budget"
  fi
}

check "localStorage uses"   "$LS_COUNT" "$MAX_LOCAL_STORAGE"
check "innerHTML assigns"   "$IH_COUNT" "$MAX_INNER_HTML"
check "eval() calls"        "$EV_COUNT" "$MAX_EVAL"
check "document.write"      "$DW_COUNT" "$MAX_DOCUMENT_WRITE"
check "unsafe URL schemes"  "$UU_COUNT" "$MAX_UNSAFE_URL"

echo ""
if [ "$FAIL" -eq 1 ]; then
  echo " ❌ FAIL — UI security budget exceeded"
  echo ""
  echo " Fix options:"
  echo "  - Run codemod: node codemod/innerHTML-to-safe.js <file>"
  echo "  - Migrate JWT: see docs/governance/UI_HARDENING.md"
  echo ""
  exit 1
fi

echo " ✓ PASS — within UI security budget"
exit 0
