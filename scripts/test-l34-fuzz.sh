#!/usr/bin/env bash
# scripts/test-l34-fuzz.sh — Go native fuzzing on parser hot-paths.
#
# `go test -fuzz=Name -fuzztime=NN` mutates seed corpus to find inputs
# that cause panics, infinite loops, or assertion failures. Targets:
#
#   35.1 auth.parseJWT       — malformed JWTs (alg confusion, NUL,
#                              base64 garbage, oversized claims)
#   35.2 auth.ClientIP       — RemoteAddr parsing
#   35.3 handler.decodeJSON  — JSON body parser
#   35.4 handler.extractTenantID — substring-based tenant extractor
#                                  used by SSE Hub routing
#
# Each target runs for FUZZTIME seconds (default 8s) — enough to
# explore boundaries without ballooning CI time. New fuzz failures
# create testdata/fuzz/<TargetName>/<hash> files; the test then
# fails on every subsequent run until fixed.
#
# Pre-flight: go installed, go.mod ≥ 1.18 (Go fuzzing landed in 1.18).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command go

FUZZTIME="${FUZZTIME:-8s}"

# run_fuzz NAME PACKAGE TARGET
# Runs `go test -fuzz=TARGET -fuzztime=$FUZZTIME` and reports pass/fail.
# A panic / assertion failure leaves a failing seed in testdata/fuzz/
# which subsequent runs replay (fast regression check).
run_fuzz() {
  local name="$1" pkg="$2" target="$3"
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  local out
  out=$(mktemp)
  local start_ts elapsed
  start_ts=$(date +%s)
  if go test -run="^$" -fuzz="^${target}\$" -fuzztime="$FUZZTIME" -timeout=$((${FUZZTIME%s} + 30))s \
       "$pkg" > "$out" 2>&1; then
    elapsed=$(( $(date +%s) - start_ts ))
    # Pull the "execs: N" line for reporting.
    execs=$(grep -oE 'execs: [0-9]+' "$out" | tail -1 | awk '{print $2}')
    interesting=$(grep -oE 'new interesting: [0-9]+' "$out" | tail -1 | awk '{print $3}')
    _pass "$name [${execs:-?} execs in ${elapsed}s, ${interesting:-?} new corpus]"
  else
    elapsed=$(( $(date +%s) - start_ts ))
    # Look for the panic / failure detail.
    detail=$(grep -E "^\s+--- FAIL|panicked|panic:" "$out" | head -3 | tr '\n' '|')
    if [[ -z "$detail" ]]; then
      detail=$(tail -8 "$out" | tr '\n' '|')
    fi
    _fail "$name" "fuzz failed after ${elapsed}s: $detail"
  fi
  rm -f "$out"
}

# ── 35.1 / 35.2 — internal/auth fuzz targets ──────────────────────────────

phase_open "35 Fuzz parsers — JWT / ClientIP / JSON / SSE tenant extract"

run_fuzz "35.1 parseJWT"          "./internal/auth"        "FuzzParseJWT"
run_fuzz "35.2 ClientIP"          "./internal/auth"        "FuzzClientIP"
run_fuzz "35.3 decodeJSON"        "./internal/api/handler" "FuzzDecodeJSON"

# ── final ──────────────────────────────────────────────────────────────────

final_summary
