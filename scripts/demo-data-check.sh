#!/usr/bin/env bash
# Chặn hardcoded demo data leak vào production
# Chạy khi VSP_ENV=production

set -euo pipefail

ENV="${VSP_ENV:-development}"

if [ "$ENV" != "production" ]; then
  echo "→ VSP_ENV=$ENV — skip demo-data check"
  exit 0
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Demo Data Leak Check (production build)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SCAN_DIRS_RAW="panels static internal/web"
EXISTING_DIRS=()
for d in $SCAN_DIRS_RAW; do
  [ -d "$d" ] && EXISTING_DIRS+=("$d")
done
[ ${#EXISTING_DIRS[@]} -eq 0 ] && EXISTING_DIRS=(".")

# Patterns indicating hardcoded demo data
PATTERNS=(
  'var\s+DEF_[A-Z]+\s*='
  'var\s+SAMPLE_[A-Z]+\s*='
  'const\s+DEMO_[A-Z]+\s*='
  'coming soon'
  'FIXME'
  'TODO:\s*remove'
  '@@FAKE@@'
  'vsp_xxxxxxxx'
)

FOUND=0
for p in "${PATTERNS[@]}"; do
  MATCHES=$(grep -rEn "$p" "${EXISTING_DIRS[@]}" \
    --include="*.html" --include="*.js" \
    --exclude-dir=node_modules --exclude-dir=.git 2>/dev/null || true)

  if [ -n "$MATCHES" ]; then
    echo ""
    echo "❌ Pattern '$p' found:"
    echo "$MATCHES" | head -5 | sed 's/^/   /'
    CNT=$(echo "$MATCHES" | wc -l)
    [ "$CNT" -gt 5 ] && echo "   ... and $((CNT - 5)) more"
    FOUND=$((FOUND + CNT))
  fi
done

echo ""
if [ "$FOUND" -gt 0 ]; then
  echo "❌ FAIL — $FOUND demo-data patterns found in production build"
  echo ""
  echo "Fix:"
  echo "  1. Move to /fixtures/<name>.json"
  echo "  2. Load conditionally:"
  echo "     if (window.VSP_DEMO_MODE) { DEF_RULES = await fetch('/fixtures/rules.json') }"
  echo ""
  exit 1
fi

echo "✓ PASS — no demo-data leaks"
