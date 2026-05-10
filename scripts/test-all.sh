#!/usr/bin/env bash
# scripts/test-all.sh — release-readiness ladder runner (L1 → L7).
#
# Runs every L-level script in order, captures pass/fail/skip per level,
# emits a final aggregate scoreboard. Designed to be the single command
# CI invokes to gate a release.
#
# Pre-flight env (set EITHER directly OR via files referenced below):
#   JWT_SECRET            — HMAC secret used to sign dev-mint tokens
#   DB_DSN                — full postgres:// URI
#   BASE                  — gateway base URL (default http://127.0.0.1:8921)
#   VSP_JWT_SECRET_FILE   — alt path to a file containing JWT_SECRET=...
#                          (useful when the canonical /etc/vsp/env.production
#                          isn't available, e.g. in CI containers)
#
# Flags:
#   --json                Emit a final JSON scoreboard to $REPORT_FILE
#                         (default: ./test-all-report.json)
#   --skip-soak           Skip the soak / long-running probes (CI mode)
#   --filter <substr>     Pass FILTER=<substr> down to runners
#
# Exit code: 0 if every level reports 0 fail; non-zero with a summary
# of which level(s) failed otherwise.
set -uo pipefail   # NOT -e: we WANT to keep going through level failures
                   # so the operator sees a complete scoreboard, not just
                   # the first red.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

# ── flags ──────────────────────────────────────────────────────────────────

JSON_REPORT=""
SKIP_SOAK=0
FILTER=""

while (( $# > 0 )); do
  case "$1" in
    --json)         JSON_REPORT="${2:-./test-all-report.json}"; shift 2 ;;
    --skip-soak)    SKIP_SOAK=1; shift ;;
    --filter)       FILTER="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0 ;;
    *) printf "unknown flag: %s\n" "$1" >&2; exit 2 ;;
  esac
done
export FILTER

# ── pre-flight ─────────────────────────────────────────────────────────────

require_command curl jq psql openssl

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable. Set JWT_SECRET env, or VSP_JWT_SECRET_FILE pointing at a readable file with JWT_SECRET=...\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi
export JWT_SECRET

if [[ -z "${DB_DSN:-}" ]]; then
  printf "%s✗%s DB_DSN env not set\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

# Mint shared admin/analyst tokens once so per-level scripts can pick
# them up via env rather than each minting their own.
export TOKEN_ADMIN=$("$ROOT/scripts/mint_jwt_local.sh" admin "$JWT_SECRET")
export TOKEN_ANALYST=$("$ROOT/scripts/mint_jwt_local.sh" analyst "$JWT_SECRET")

# ── per-level invocations ──────────────────────────────────────────────────

declare -A LEVEL_RESULT  # key=level → "pass:fail:skip:total:duration_s"
declare -a LEVEL_ORDER

# run_level NAME SCRIPT [ARGS...]
# Captures the runner's stdout, parses the final "PASS:N FAIL:N SKIP:N"
# block, and stores under LEVEL_RESULT.
run_level() {
  local key="$1" script="$2"; shift 2
  LEVEL_ORDER+=("$key")
  printf "\n%s═══ %s ═══%s\n" "$C_BOLD" "$key" "$C_RESET"
  local out start_ts elapsed
  out=$(mktemp)
  start_ts=$(date +%s)
  "$script" "$@" > "$out" 2>&1
  elapsed=$(( $(date +%s) - start_ts ))

  # Tail the output so the operator sees per-test pass/fail.
  tail -25 "$out"

  # Parse the script's own summary block.
  local pass fail skip total
  pass=$(grep -E "^\s*PASS:" "$out" | tail -1 | grep -Eo '[0-9]+' | tail -1)
  fail=$(grep -E "^\s*FAIL:" "$out" | tail -1 | grep -Eo '[0-9]+' | tail -1)
  skip=$(grep -E "^\s*SKIP:" "$out" | tail -1 | grep -Eo '[0-9]+' | tail -1)
  total=$(grep -E "^\s*Total:" "$out" | tail -1 | grep -Eo '[0-9]+' | tail -1)
  pass=${pass:-0}; fail=${fail:-0}; skip=${skip:-0}; total=${total:-0}

  LEVEL_RESULT["$key"]="$pass:$fail:$skip:$total:$elapsed"
  rm -f "$out"
}

# run_go_level NAME GO_TEST_ARGS
# Wraps `go test` and synthesizes pass/fail count from -v output.
run_go_level() {
  local key="$1"; shift
  LEVEL_ORDER+=("$key")
  printf "\n%s═══ %s ═══%s\n" "$C_BOLD" "$key" "$C_RESET"
  local out start_ts elapsed
  out=$(mktemp)
  start_ts=$(date +%s)
  go test -count=1 -v "$@" > "$out" 2>&1
  elapsed=$(( $(date +%s) - start_ts ))
  tail -20 "$out"
  local pass fail
  pass=$(grep -c "^--- PASS:" "$out" || true)
  fail=$(grep -c "^--- FAIL:" "$out" || true)
  LEVEL_RESULT["$key"]="$pass:$fail:0:$((pass+fail)):$elapsed"
  rm -f "$out"
}

# Order matters: cheap probes first; level that triggers IPLockout
# (L5) goes near the end so subsequent levels don't get rate-limited.
run_level "L1 smoke"            "$ROOT/scripts/test-l1-smoke.sh"
run_level "L2 feature"          "$ROOT/scripts/test-l2-feature.sh"
run_go_level "L4-A property"    "./internal/gate/" -run TestProp
run_level "L4-B multi-tenant"   "$ROOT/scripts/test-l4-tenant-isolation.sh"
run_level "L6-A db-integrity"   "$ROOT/scripts/test-l6-db-integrity.sh"
run_level "L3 comprehensive"    "$ROOT/scripts/test-l3-comprehensive.sh" all
run_level "L5 advanced"         "$ROOT/scripts/test-l5-advanced.sh"
run_level "L8 security-depth"   "$ROOT/scripts/test-l8-security-depth.sh"
run_level "L9 lifecycle"        "$ROOT/scripts/test-l9-lifecycle.sh"
run_level "L10 openapi"         "$ROOT/scripts/test-l10-openapi.sh"
run_level "L11 mutation"        "$ROOT/scripts/test-l11-mutation.sh"
run_level "L13 frontend"        "$ROOT/scripts/test-l13-frontend.sh"
run_level "L15 http-hygiene"    "$ROOT/scripts/test-l15-http-hygiene.sh"
run_level "L16 info-disclosure" "$ROOT/scripts/test-l16-info-disclosure.sh"
run_level "L17 ratelimit"       "$ROOT/scripts/test-l17-ratelimit.sh"
run_level "L18 migration"       "$ROOT/scripts/test-l18-migration-safety.sh"
run_level "L19 redos"           "$ROOT/scripts/test-l19-redos.sh"
run_level "L20 deps-license"    "$ROOT/scripts/test-l20-deps-license.sh"
run_level "L21 upload-safety"   "$ROOT/scripts/test-l21-upload-safety.sh"
run_level "L22 sqli"            "$ROOT/scripts/test-l22-sqli.sh"
run_level "L23 trust-boundary"  "$ROOT/scripts/test-l23-trust-boundary.sh"
run_level "L24 input-validation" "$ROOT/scripts/test-l24-input-validation.sh"
run_level "L25 race-toctou"     "$ROOT/scripts/test-l25-race-toctou.sh"
run_level "L26 resource-cleanup" "$ROOT/scripts/test-l26-resource-cleanup.sh"
run_level "L27 observability"   "$ROOT/scripts/test-l27-observability.sh"
run_level "L28 secrets"         "$ROOT/scripts/test-l28-secrets.sh"
run_level "L29 time-correctness" "$ROOT/scripts/test-l29-time-correctness.sh"
run_level "L30 container-deploy" "$ROOT/scripts/test-l30-container-deploy.sh"
run_level "L32 bypass"          "$ROOT/scripts/test-l32-bypass.sh"
run_level "L33 semgrep"         "$ROOT/scripts/test-l33-semgrep.sh"
run_level "L34 fuzz"            "$ROOT/scripts/test-l34-fuzz.sh"

# L12 chaos and L14 perf are gated — they mutate the live environment
# (stop redis, kill PG conns, sustained burst). Enable explicitly
# in the contexts where that's acceptable.
if [[ "${RUN_CHAOS:-0}" == "1" ]]; then
  run_level "L12 chaos"         "$ROOT/scripts/test-l12-chaos.sh"
fi
if [[ "${RUN_PERF:-0}" == "1" ]]; then
  run_level "L14 perf-smoke"    "$ROOT/scripts/test-l14-perf.sh"
fi

# L7 (DSR erasure) only runs when explicitly enabled — it mutates DB
# state and is destructive in a way the others aren't.
if [[ "${RUN_L7:-0}" == "1" ]]; then
  run_level "L7 DSR-residue"    "$ROOT/scripts/test-l7-dsr-residue.sh"
fi

# ── final scoreboard ───────────────────────────────────────────────────────

printf "\n%s════════════════ Release-readiness scoreboard ════════════════%s\n" "$C_BOLD" "$C_RESET"
printf "  %-25s  %6s  %6s  %6s  %6s  %6s\n" "Level" "PASS" "FAIL" "SKIP" "Total" "Time"
printf "  %-25s  %6s  %6s  %6s  %6s  %6s\n" "-----" "----" "----" "----" "-----" "----"

TOTAL_PASS=0 TOTAL_FAIL=0 TOTAL_SKIP=0 TOTAL=0
for key in "${LEVEL_ORDER[@]}"; do
  IFS=':' read -r p f s t e <<<"${LEVEL_RESULT[$key]}"
  local_color="$C_GREEN"
  (( f > 0 )) && local_color="$C_RED"
  printf "  %-25s  %s%6s%s  %s%6s%s  %6s  %6s  %5ss\n" \
    "$key" "$C_GREEN" "$p" "$C_RESET" "$local_color" "$f" "$C_RESET" "$s" "$t" "$e"
  TOTAL_PASS=$((TOTAL_PASS + p))
  TOTAL_FAIL=$((TOTAL_FAIL + f))
  TOTAL_SKIP=$((TOTAL_SKIP + s))
  TOTAL=$((TOTAL + t))
done
printf "  %-25s  %s%6s%s  %s%6s%s  %6s  %6s\n" \
  "Cumulative" \
  "$C_GREEN" "$TOTAL_PASS" "$C_RESET" \
  "$([[ "$TOTAL_FAIL" -gt 0 ]] && echo "$C_RED" || echo "$C_GREEN")" "$TOTAL_FAIL" "$C_RESET" \
  "$TOTAL_SKIP" "$TOTAL"

# Optional JSON report.
if [[ -n "$JSON_REPORT" ]]; then
  {
    printf '{\n  "cumulative":{"pass":%d,"fail":%d,"skip":%d,"total":%d},\n  "levels":{\n' \
      "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_SKIP" "$TOTAL"
    first=1
    for key in "${LEVEL_ORDER[@]}"; do
      IFS=':' read -r p f s t e <<<"${LEVEL_RESULT[$key]}"
      [[ $first -eq 1 ]] || printf ",\n"
      first=0
      printf '    "%s":{"pass":%d,"fail":%d,"skip":%d,"total":%d,"duration_s":%d}' \
        "$key" "$p" "$f" "$s" "$t" "$e"
    done
    printf '\n  },\n  "generated_at":"%s"\n}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$JSON_REPORT"
  printf "\n  JSON report → %s\n" "$JSON_REPORT"
fi

# Exit code.
if (( TOTAL_FAIL > 0 )); then
  printf "\n%s✗%s release blocked — %d failure(s) across %d level(s)\n" \
    "$C_RED" "$C_RESET" "$TOTAL_FAIL" "${#LEVEL_ORDER[@]}"
  exit 1
fi
printf "\n%s✓%s release-ready — %d active checks, 0 failure\n" \
  "$C_GREEN" "$C_RESET" "$TOTAL_PASS"
exit 0
