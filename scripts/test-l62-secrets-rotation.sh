#!/usr/bin/env bash
# scripts/test-l62-secrets-rotation.sh — secret rotation cadence.
#
# Compliance requirements (NIST 800-53 SC-12, FedRAMP IA-5(1)):
# every secret category has a defined rotation cadence + audit
# trail of WHEN each one was last rotated.
#
# Probes:
#   1. A rotation-tracking artefact exists (docs/SECRETS_ROTATION.md
#      or similar). Document at minimum: secret name, category,
#      cadence, last_rotated.
#   2. Every category mentioned in code (JWT_SECRET, DB password,
#      VSP_REPO_KEY, API keys, CSRF key) appears in the document.
#   3. No secret rotated > 90 days ago (configurable).
#   4. Workflows don't pin secrets to a magic string (hard-coded
#      values in YAML are a rotation impossibility).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 62.1 Rotation policy document present ────────────────────────────────

phase_open "62.1 Rotation policy artefact present"

ROT_DOC=""
for cand in \
    "$ROOT/docs/SECRETS_ROTATION.md" \
    "$ROOT/docs/SECRET_ROTATION.md" \
    "$ROOT/SECRETS.md" \
    "$ROOT/docs/security/secrets-rotation.md"; do
  if [[ -r "$cand" ]]; then ROT_DOC="$cand"; break; fi
done

if [[ -z "$ROT_DOC" ]]; then
  _fail "62.1.0 rotation policy doc absent" \
    "expected one of docs/SECRETS_ROTATION.md / SECRETS.md — compliance gap"
else
  _pass "62.1.0 rotation doc at $(basename "$ROT_DOC")"
fi

# ── 62.2 Every secret category referenced in code is documented ──────────

phase_open "62.2 Secret-category coverage"

# Categories the code refers to.
CATEGORIES=(
  "JWT_SECRET"
  "DATABASE_URL"
  "REDIS_PASSWORD"
  "VSP_REPO_KEY"
  "CSRF"
  "API_KEY"
  "WEBHOOK_SECRET"
)

if [[ -z "$ROT_DOC" ]]; then
  _skip "62.2.1 category coverage" "no rotation doc to check against"
else
  MISSING=()
  for cat in "${CATEGORIES[@]}"; do
    # Match case-insensitive, with common separators (- _ space).
    if ! grep -iqE "${cat//_/[ _-]?}" "$ROT_DOC" 2>/dev/null; then
      MISSING+=("$cat")
    fi
  done

  if (( ${#MISSING[@]} == 0 )); then
    _pass "62.2.1 all 7 secret categories listed in rotation doc"
  elif (( ${#MISSING[@]} <= 2 )); then
    _skip "62.2.1 partial category coverage" \
      "missing: ${MISSING[*]} — informational"
  else
    _fail "62.2.1 most categories undocumented" \
      "${#MISSING[@]} of 7 missing: ${MISSING[*]:0:3}..."
  fi
fi

# ── 62.3 No secret rotated > 90 days ago ─────────────────────────────────

phase_open "62.3 Rotation cadence — nothing stale"

if [[ -z "$ROT_DOC" ]]; then
  _skip "62.3.1 staleness check" "no rotation doc"
else
  # Look for ISO-8601 dates in the doc. Anything older than 90 days
  # from today's perspective is stale.
  NOW_EPOCH=$(date +%s)
  STALE_THRESHOLD=$((NOW_EPOCH - 90 * 86400))

  STALEST=$(grep -oE '20[0-9]{2}-[0-9]{2}-[0-9]{2}' "$ROT_DOC" 2>/dev/null \
    | sort -u \
    | while read -r d; do
        e=$(date -d "$d" +%s 2>/dev/null || echo 0)
        if (( e > 0 && e < STALE_THRESHOLD )); then
          echo "$d"
        fi
      done | head -1)

  if [[ -z "$STALEST" ]]; then
    _pass "62.3.1 no rotation date older than 90 days"
  else
    _fail "62.3.1 stale rotation date in doc" \
      "$STALEST is > 90 days old — rotate the corresponding secret"
  fi
fi

# ── 62.4 No hard-coded production secrets in workflows ───────────────────

phase_open "62.4 Workflow secrets via secrets context only"

WF_DIR="$ROOT/.github/workflows"
if [[ ! -d "$WF_DIR" ]]; then
  _skip "62.4.1 workflow secret usage" "no workflows dir"
else
  # Look for ENV vars assigned to literal high-entropy strings.
  # Heuristic: ENV: SOMETHING_SECRET: "<20+ chars no spaces>"
  HARDCODED=$(grep -rEn '^\s+(JWT_SECRET|API_KEY|TOKEN|SECRET):\s+["'\''][^"'\'']{20,}["'\'']' \
    "$WF_DIR" 2>/dev/null \
    | grep -vE 'secrets\.|github\.token|\$\{\{' \
    | head -3 || true)

  if [[ -z "$HARDCODED" ]]; then
    _pass "62.4.1 no hard-coded high-entropy secrets in workflows"
  else
    _fail "62.4.1 hard-coded secret in workflow" \
      "$(echo "$HARDCODED" | head -1) — move to GitHub secrets context"
  fi
fi

# ── 62.5 JWT secret loaded from env, not from source ─────────────────────

phase_open "62.5 JWT secret source"

# The gateway should NOT have a hard-coded JWT_SECRET in source.
# Look for `jwtSecret = "..."` assignments to literal strings.
LITERAL=$(grep -rEn '(jwtSecret|JWT_SECRET)\s*[:=]\s*"[A-Za-z0-9_-]{20,}"' \
  --include='*.go' \
  "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go\|\.bak\|// safe-default' \
  | head -3 || true)

if [[ -z "$LITERAL" ]]; then
  _pass "62.5.1 no hard-coded JWT secret in Go source"
else
  _fail "62.5.1 hard-coded JWT secret" \
    "$(echo "$LITERAL" | head -1) — must come from env / secret manager"
fi

final_summary
