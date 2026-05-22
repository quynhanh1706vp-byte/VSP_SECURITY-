#!/usr/bin/env bash
# scripts/test-l19-redos.sh — ReDoS (regex denial-of-service) static scan.
#
# Hand-rolled ReDoS detector — no external tools, just structural pattern
# matching against every regexp.MustCompile / regexp.Compile call site.
# Catastrophic backtracking happens with three classes of pattern:
#
#   A. Nested quantifiers:    (a+)+ , (a*)*, (a*)+
#   B. Alternation + repeat:  (a|a)+ , (a|aa)+
#   C. Optional + greedy:     (a?)+a , a*a*
#
# Go's regexp uses RE2, which is IMMUNE to most ReDoS — but if any code
# pulls a third-party regex engine (regexp/syntax with custom executor,
# or shells out to a non-RE2 lib), or if a pattern is fed user input
# without an anchored size cap, the issue resurfaces.
#
# This level pins the contract: every regex compiled in our binary is
# (a) RE2 (Go's stdlib regexp), and (b) doesn't contain the structural
# shapes most likely to be expensive even on RE2 (which can still be
# slow on pathological inputs without budget). It also flags any
# regex compiled from USER-CONTROLLABLE INPUT (catastrophic if the
# attacker gets to pick the pattern).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command grep

# ── 20.1 Only Go's stdlib regexp imported ──────────────────────────────────

phase_open "20.1 Regex engine — Go stdlib only (no external)"

EXTERNAL_RE=$(grep -rn '"regex" \|"github.com/dlclark/regexp2"\|"github.com/grafana/regexp"' \
  --include="*.go" -- "$ROOT/internal" "$ROOT/cmd" 2>/dev/null \
  | grep -v "_test\|\.bak" || true)

if [[ -z "$EXTERNAL_RE" ]]; then
  _pass "20.1.1 only stdlib regexp in use [RE2 — immune to most ReDoS]"
else
  _fail "20.1.1 external regex engine" "$EXTERNAL_RE"
fi

# ── 20.2 Static patterns — no nested quantifier shapes ─────────────────────

phase_open "20.2 Static regex patterns — no nested quantifiers"

# Find every regexp.MustCompile / regexp.Compile call and extract the
# raw pattern. Look for:
#   (foo+)+   — outer quantifier on a group whose body has +/*
#   (foo*)+   — same
#   (foo|bar)+ where bar starts with foo — alternation overlap
#   .*.*      — multiple wildcards in sequence
DANGEROUS=()
while IFS= read -r line; do
  # Extract everything between the first " and the matching " on this
  # call. (Simple heuristic; we accept some false negatives.)
  pat=$(echo "$line" | grep -oE '"[^"]*"' | head -1 | tr -d '"')
  [[ -z "$pat" ]] && continue
  # Class A — quantifier-on-quantifier.
  if echo "$pat" | grep -qE '\([^()]*[+*][^()]*\)[+*]'; then
    DANGEROUS+=("CLASS_A nested-quantifier: $line")
    continue
  fi
  # Class B — multiple greedy wildcards.
  if echo "$pat" | grep -qE '\.\*\.\*|\.\+\.\+'; then
    DANGEROUS+=("CLASS_B greedy-wildcard-chain: $line")
    continue
  fi
  # Class C — alternation with overlapping prefix.
  if echo "$pat" | grep -qE '\([a-z]+\|[a-z]+\)[+*]'; then
    # Quick over-flag: alternation+quantifier. Filter false positives
    # where alternation branches don't share a prefix.
    DANGEROUS+=("CLASS_C alt-quantifier: $line")
    continue
  fi
done < <(grep -rn 'regexp\.MustCompile\(\|regexp\.Compile\(' \
         --include="*.go" -- "$ROOT/internal" "$ROOT/cmd" 2>/dev/null \
         | grep -v "_test\|\.bak")

if (( ${#DANGEROUS[@]} == 0 )); then
  _pass "20.2.1 no nested-quantifier / greedy-chain / alt-quantifier patterns"
else
  printf -v LIST '%s | ' "${DANGEROUS[@]:0:3}"
  _fail "20.2.1 ${#DANGEROUS[@]} suspicious patterns" "${LIST%| }"
fi

# ── 20.3 No regex compiled from user-controllable input ────────────────────

phase_open "20.3 No user-input → regex compile"

# regex.Compile / MustCompile called with a NON-LITERAL argument is
# the killer pattern. RE2 mitigates ReDoS in pattern complexity but
# doesn't bound input size, and an attacker who controls the pattern
# can match against giant captures.
NONLITERAL=$(grep -rn 'regexp\.MustCompile\(\|regexp\.Compile\(' \
  --include="*.go" -- "$ROOT/internal" "$ROOT/cmd" 2>/dev/null \
  | grep -v "_test\|\.bak" \
  | grep -vE 'MustCompile\("|Compile\("' \
  | grep -vE 'regexp\.MustCompile\(`|regexp\.Compile\(`' || true)

if [[ -z "$NONLITERAL" ]]; then
  _pass "20.3.1 every regex compiled from a string literal (RE2 + safe)"
else
  HITS=$(echo "$NONLITERAL" | head -3 | tr '\n' '|')
  _fail "20.3.1 regex compiled from non-literal" "$HITS"
fi

# ── 20.4 Repeated re-compilation in hot paths ──────────────────────────────

phase_open "20.4 Re-compile not in hot loop"

# Compiling a regex inside a request handler is wasteful but not a
# ReDoS bug per se. We flag for review when MustCompile appears
# inside a function body that's clearly a handler (HandlerFunc or
# http.HandlerFunc signature in the same file).
HOT_RECOMPILE=$(grep -rln 'regexp\.MustCompile\|regexp\.Compile' \
  --include="*.go" -- "$ROOT/internal/api/handler" 2>/dev/null \
  | grep -v "_test\|\.bak" || true)

if [[ -z "$HOT_RECOMPILE" ]]; then
  _pass "20.4.1 no regex compiled inside handler files [package-level only]"
else
  # Determine if the call is at package level (var = MustCompile) vs
  # inside a func body. Heuristic: scan for MustCompile inside a
  # function (`func ... {` open brace then the call).
  PACKAGE_LEVEL=0
  IN_FUNCS=()
  while IFS= read -r f; do
    in_func=0; depth=0; hit=""
    while IFS= read -r line; do
      if [[ "$line" =~ ^func ]]; then in_func=1; depth=0; fi
      if (( in_func == 1 )); then
        depth=$((depth + $(echo "$line" | tr -cd '{' | wc -c) - $(echo "$line" | tr -cd '}' | wc -c)))
        if echo "$line" | grep -qE 'regexp\.(Must)?Compile'; then
          hit="$line"
        fi
        if (( depth == 0 )) && [[ -n "$hit" ]]; then
          IN_FUNCS+=("$(basename "$f"): $hit")
          hit=""; in_func=0
        fi
      else
        if echo "$line" | grep -qE 'regexp\.(Must)?Compile'; then
          PACKAGE_LEVEL=$((PACKAGE_LEVEL+1))
        fi
      fi
    done < "$f"
  done <<<"$HOT_RECOMPILE"

  if (( ${#IN_FUNCS[@]} == 0 )); then
    _pass "20.4.1 every handler regex compiled at package level [$PACKAGE_LEVEL sites]"
  else
    printf -v L '%s | ' "${IN_FUNCS[@]:0:3}"
    _fail "20.4.1 regex compiled inside handler function" "${L%| }"
  fi
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
