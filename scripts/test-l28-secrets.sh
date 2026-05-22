#!/usr/bin/env bash
# scripts/test-l28-secrets.sh — hardcoded secrets / credentials scan.
#
# Three layers:
#
#   29.1 Source code — grep for high-entropy strings or credential
#        patterns (password=, api_key=, secret=, BEGIN PRIVATE KEY)
#        in tracked .go / .yaml / .yml / .json / .sh files.
#
#   29.2 Config files — config/*.yaml and similar must not contain
#        non-placeholder secrets. Allowed: ${ENV_VAR}, $(secret), or
#        explicitly-marked "REPLACE_ME" / "CHANGE_ME".
#
#   29.3 Repository surface — confirm gitignore covers .env, *.pem,
#        secrets.yaml, etc. Drift here means a future commit could
#        accidentally publish a secret.
#
# Pre-flight: grep, git.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command grep git

cd "$ROOT"

# ── 29.1 Source code — credential patterns ────────────────────────────────

phase_open "29.1 Source — no hardcoded credentials"

# Pattern: assignment-of-credential-like token. We exclude lines
# inside test files, _test.go, comments (//), markdown code blocks,
# and obvious example strings (REPLACE_ME, dev-secret-please-change,
# test-only). Also exclude binary file paths.
LEAKS=()

# Real credentials look like:
#   password = "concrete-string"
#   api_key = "AKIA..."
#   private_key = "-----BEGIN ..."
# We focus on string-literal assignments only (so we don't flag
# struct field NAMES like Password string).
while IFS= read -r line; do
  # Skip obvious safe values.
  if echo "$line" | grep -qiE "REPLACE_ME|CHANGE_ME|YOUR_[A-Z_]+_HERE|EXAMPLE|placeholder|dev-secret-please-change|test-secret|fake-?secret|sample"; then
    continue
  fi
  # Skip env-var references and func-call values.
  if echo "$line" | grep -qiE 'os\.Getenv|viper\.|GetString|GetEnv|getenv|env\.(Var|Get)|secrets?\.Get|\$\{|\$\('; then
    continue
  fi
  # Skip empty-string literals (`= ""`) — clearly not a leak.
  if echo "$line" | grep -qE '=\s*"\s*"'; then
    continue
  fi
  LEAKS+=("$line")
done < <(grep -rEn '(password|passwd|api_?key|secret|token|private_key)\s*[:=]\s*"[A-Za-z0-9_\-./+]{12,}"' \
  --include="*.go" --include="*.yaml" --include="*.yml" --include="*.json" --include="*.toml" \
  --include="*.sh" \
  -- "$ROOT" 2>/dev/null \
  | grep -vE "_test\.go|/\.bak\.|//|/test/|\.bak$|test-l[0-9]+|README|/migrations/" )

if (( ${#LEAKS[@]} == 0 )); then
  _pass "29.1.1 no hardcoded credentials in source/yaml/json/sh"
else
  printf -v LIST '%s | ' "${LEAKS[@]:0:3}"
  _fail "29.1.1 ${#LEAKS[@]} potential hardcoded credentials" "${LIST%| }"
fi

# 29.1.2 — BEGIN PRIVATE KEY blocks anywhere in tracked source.
KEYS=$(grep -rEln "BEGIN (RSA|EC|OPENSSH|PRIVATE) (PRIVATE )?KEY" \
  -- "$ROOT/cmd" "$ROOT/internal" "$ROOT/scripts" "$ROOT/config" 2>/dev/null \
  | grep -vE "_test|\.bak|/\.git/|/test-l28-secrets\.sh$" || true)

if [[ -z "$KEYS" ]]; then
  _pass "29.1.2 no PEM-format private keys committed"
else
  HITS=$(echo "$KEYS" | head -3 | tr '\n' '|')
  _fail "29.1.2 PEM private key committed" "$HITS"
fi

# ── 29.2 Config files — placeholders only ─────────────────────────────────

phase_open "29.2 Config — secrets only via env-var refs / placeholders"

# Walk config/*.yaml and look for VALUE lines that look like a secret
# (high-entropy hex/base64) AND are NOT clearly a placeholder.
LEAKS=()
for f in "$ROOT"/config/*.yaml "$ROOT"/config/*.yml; do
  [[ -f "$f" ]] || continue
  while IFS= read -r line; do
    # Skip comments, blanks, env-refs.
    if echo "$line" | grep -qE '^\s*(#|$)'; then continue; fi
    if echo "$line" | grep -qiE '\$\{|\$\(|env:|fromEnv|REPLACE_ME|CHANGE_ME'; then continue; fi
    # Look for value=high-entropy. We accept short tokens (< 12 chars).
    if echo "$line" | grep -qE ':\s*"?[A-Za-z0-9_/+]{32,}"?\s*$'; then
      LEAKS+=("$(basename "$f"): $line")
    fi
  done < "$f"
done

if (( ${#LEAKS[@]} == 0 )); then
  _pass "29.2.1 config files contain no high-entropy secret-shaped values"
else
  printf -v LIST '%s | ' "${LEAKS[@]:0:3}"
  _fail "29.2.1 config contains potential secret value" "${LIST%| }"
fi

# ── 29.3 .gitignore covers secret-bearing paths ───────────────────────────

phase_open "29.3 .gitignore — covers .env / *.pem / secrets.* paths"

GI="$ROOT/.gitignore"
if [[ ! -f "$GI" ]]; then
  _fail "29.3.1 .gitignore missing" "no .gitignore at repo root"
else
  REQUIRED=( ".env" "*.pem" "secrets" )
  MISSING=()
  for pat in "${REQUIRED[@]}"; do
    # Match if any line of .gitignore STARTS with the literal pattern,
    # possibly followed by `/`, `.`, whitespace, or EOL. We use grep -F
    # for fixed-string match against the prefix, then a tail check.
    if ! awk -v p="$pat" '
      {
        line=$0
        sub(/^[[:space:]]+/, "", line)
        if (index(line, p) == 1) {
          rest = substr(line, length(p)+1, 1)
          if (rest == "" || rest == "/" || rest == "." || rest == " " || rest == "\t") {
            found=1
          }
        }
      }
      END { exit !found }' "$GI"; then
      MISSING+=("$pat")
    fi
  done
  if (( ${#MISSING[@]} == 0 )); then
    _pass "29.3.1 .gitignore covers .env / *.pem / secrets/"
  else
    _fail "29.3.1 .gitignore missing patterns" "${MISSING[*]}"
  fi
fi

# 29.3.2 — confirm no .env file is currently TRACKED in git (a fresh
# git ls-files | grep \.env$ should come back empty).
TRACKED_ENV=$(git ls-files 2>/dev/null | grep -E '(^|/)\.env$' || true)
if [[ -z "$TRACKED_ENV" ]]; then
  _pass "29.3.2 no .env file tracked in git"
else
  _fail "29.3.2 .env file tracked" "$TRACKED_ENV"
fi

# 29.3.3 — confirm no .pem file is tracked.
TRACKED_PEM=$(git ls-files 2>/dev/null | grep -E '\.pem$|\.key$' || true)
if [[ -z "$TRACKED_PEM" ]]; then
  _pass "29.3.3 no PEM/key files tracked in git"
else
  _fail "29.3.3 PEM/key file tracked" "$TRACKED_PEM"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
