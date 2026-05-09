# shellcheck shell=bash
# vsp-test.sh — shared test helpers for VSP test runners.
#
# Source this from a runner script:
#   . "$(dirname "$0")/lib/vsp-test.sh"
#
# Provides:
#   • assert_status URL EXPECTED_CODE [HEADERS...]
#   • assert_json   URL JQ_FILTER EXPECTED_VALUE [HEADERS...]
#   • assert_json_min_size URL MIN_BYTES [HEADERS...]
#   • assert_db_query SQL EXPECTED_OUTPUT
#   • assert_eq NAME ACTUAL EXPECTED
#   • skip NAME REASON
#   • phase_open NAME, phase_close
#   • final_summary  → exit 0 if all pass, 1 if any fail
#
# Convention:
#   $BASE       — gateway base URL (default http://127.0.0.1:8921)
#   $TOKEN_ADMIN, $TOKEN_ANALYST — JWTs
#   $DB_DSN     — full postgres URI (or set $PG* env)
#   $FILTER     — only run tests matching this substring (optional)

# shellcheck disable=SC2034  # globals consumed by runners
BASE="${BASE:-http://127.0.0.1:8921}"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
CURRENT_PHASE=""
declare -a FAIL_LOG=()

# Colour output if terminal supports it.
if [[ -t 1 ]]; then
  C_GREEN=$'\033[32m' C_RED=$'\033[31m' C_AMBER=$'\033[33m'
  C_DIM=$'\033[2m' C_BOLD=$'\033[1m' C_RESET=$'\033[0m'
else
  C_GREEN="" C_RED="" C_AMBER="" C_DIM="" C_BOLD="" C_RESET=""
fi

# ── output ─────────────────────────────────────────────────────────────────

phase_open() {
  CURRENT_PHASE="$1"
  printf "\n%s── %s ──%s\n" "$C_BOLD" "$1" "$C_RESET"
}

phase_close() { CURRENT_PHASE=""; }

# Pretty-print pass / fail / skip lines.
_pass() { PASS_COUNT=$((PASS_COUNT+1)); printf "  %s✓%s %s\n" "$C_GREEN" "$C_RESET" "$1"; }
_fail() {
  FAIL_COUNT=$((FAIL_COUNT+1))
  printf "  %s✗%s %s\n     %s%s%s\n" "$C_RED" "$C_RESET" "$1" "$C_DIM" "$2" "$C_RESET"
  FAIL_LOG+=("$CURRENT_PHASE :: $1 :: $2")
}
_skip() { SKIP_COUNT=$((SKIP_COUNT+1)); printf "  %s○%s %s %s(%s)%s\n" "$C_AMBER" "$C_RESET" "$1" "$C_DIM" "$2" "$C_RESET"; }

# Run only if test name matches FILTER (when set).
_should_run() {
  [[ -z "${FILTER:-}" ]] && return 0
  [[ "$1" == *"$FILTER"* ]]
}

# ── HTTP probes ────────────────────────────────────────────────────────────

# assert_status NAME URL EXPECTED_CODE [HEADERS_AS_-H_FLAGS...]
# EXPECTED_CODE may be a single code "200" or pipe-separated "401|403"
# to accept either. Common case: CSRF-protected POSTs return 403
# before auth middleware fires (so unauth probe returns 403, not 401).
# E.g. assert_status "1.1 alive" /api/v1/auth/check 200 -H "Authorization: Bearer $TOKEN"
assert_status() {
  local name="$1"; local url="$2"; local want="$3"; shift 3
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  local got
  # -L follows up to 5 redirects so static files served via
  # chimw.StripSlashes (which 301s e.g. /trust/index.html → /trust/index.html
  # then serves) reach their final 200.
  got=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 10 --max-redirs 5 "$@" "$BASE$url" 2>/dev/null) || got="000"
  # Match either a single expected code or pipe-separated list.
  local matched=0
  local IFS='|'
  for code in $want; do
    [[ "$got" == "$code" ]] && matched=1
  done
  unset IFS
  if (( matched == 1 )); then
    _pass "$name [$got]"
  else
    _fail "$name" "expected HTTP $want, got $got — URL: $url"
  fi
}

# assert_json NAME URL JQ_FILTER EXPECTED [HEADERS...]
# Sends GET, parses with jq, compares to expected. JQ_FILTER as in
# `curl ... | jq -r '.field'`.
assert_json() {
  local name="$1"; local url="$2"; local filter="$3"; local want="$4"; shift 4
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  local body status
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 10 "$@" "$BASE$url" 2>/dev/null) || status="000"
  if [[ "$status" != "200" ]]; then
    _fail "$name" "HTTP $status (expected 200 for jq probe)"
    rm -f "$body"; return
  fi
  local got
  got=$(jq -r "$filter" "$body" 2>/dev/null) || got="<jq-error>"
  rm -f "$body"
  if [[ "$got" == "$want" ]]; then
    _pass "$name [$filter == \"$want\"]"
  else
    _fail "$name" "$filter expected \"$want\", got \"$got\""
  fi
}

# assert_json_min_size NAME URL MIN_BYTES [HEADERS...]
# Used when we just want to confirm "endpoint returns non-trivial JSON".
assert_json_min_size() {
  local name="$1"; local url="$2"; local min="$3"; shift 3
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  local body size status
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 10 "$@" "$BASE$url" 2>/dev/null) || status="000"
  size=$(wc -c < "$body" | tr -d ' ')
  rm -f "$body"
  if [[ "$status" == "200" && "$size" -ge "$min" ]]; then
    _pass "$name [$size B ≥ $min B]"
  else
    _fail "$name" "HTTP $status, size $size B (need ≥ $min B and HTTP 200)"
  fi
}

# assert_jq_count NAME URL JQ_FILTER MIN_COUNT [HEADERS...]
# JQ_FILTER must yield an array; passes when length >= MIN_COUNT.
assert_jq_count() {
  local name="$1"; local url="$2"; local filter="$3"; local min="$4"; shift 4
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  local body status got
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 10 "$@" "$BASE$url" 2>/dev/null) || status="000"
  got=$(jq -r "$filter | length" "$body" 2>/dev/null) || got=-1
  rm -f "$body"
  if [[ "$status" == "200" && "$got" -ge "$min" ]]; then
    _pass "$name [$got items ≥ $min]"
  else
    _fail "$name" "HTTP $status, count $got (need ≥ $min and HTTP 200)"
  fi
}

# ── DB probes ──────────────────────────────────────────────────────────────

# assert_db_query NAME SQL EXPECTED_VALUE
# Runs SQL via psql, compares first cell of output to expected.
assert_db_query() {
  local name="$1"; local sql="$2"; local want="$3"
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  if ! command -v psql &>/dev/null; then
    _skip "$name" "psql not installed"
    return
  fi
  local got
  # _psql_oneshot already filters "Pager usage" + empty lines and
  # returns first data line. Trim only outer whitespace, preserve
  # internal spaces (in case caller queries text columns).
  got=$(_psql_oneshot "$sql" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  if [[ "$got" == "$want" ]]; then
    _pass "$name [SQL → $got]"
  else
    _fail "$name" "SQL → \"$got\" (expected \"$want\")"
  fi
}

_psql_oneshot() {
  # PAGER=cat + --no-psqlrc + --pset pager=off — many systems have a
  # pager hint in psqlrc that prints "Pager usage is off." to stdout
  # before the actual result. -tA suppresses headers/format but not
  # psqlrc output. The triple-belt approach below silences it.
  local out
  if [[ -n "${DB_DSN:-}" ]]; then
    out=$(PAGER=cat psql -X -tA --pset pager=off -d "$DB_DSN" -c "$1" 2>/dev/null)
  else
    out=$(PAGER=cat psql -X -tA --pset pager=off \
      -h "${PGHOST:-localhost}" -U "${PGUSER:-vsp}" -d "${PGDATABASE:-vsp_go}" -c "$1" 2>/dev/null)
  fi
  # Filter out any residual "Pager usage is off." line that some psql
  # versions print regardless of -X / pager=off.
  printf "%s\n" "$out" | grep -v -i "pager usage" | grep -v "^$" | head -1
}

# ── unit-level ─────────────────────────────────────────────────────────────

assert_eq() {
  local name="$1"; local got="$2"; local want="$3"
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  if [[ "$got" == "$want" ]]; then
    _pass "$name"
  else
    _fail "$name" "got \"$got\", expected \"$want\""
  fi
}

# Skip a test deliberately (e.g. requires browser, manual verification, or
# external dependency not present).
skip() {
  _should_run "$1" || return
  _skip "$1" "$2"
}

# ── final ──────────────────────────────────────────────────────────────────

final_summary() {
  local total=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
  printf "\n%s═══ Result ═══%s\n" "$C_BOLD" "$C_RESET"
  printf "  %sPASS:  %d%s\n" "$C_GREEN" "$PASS_COUNT" "$C_RESET"
  printf "  %sFAIL:  %d%s\n" "$C_RED" "$FAIL_COUNT" "$C_RESET"
  printf "  %sSKIP:  %d%s\n" "$C_AMBER" "$SKIP_COUNT" "$C_RESET"
  printf "  Total: %d\n" "$total"
  if (( FAIL_COUNT > 0 )); then
    printf "\n%sFailures:%s\n" "$C_RED" "$C_RESET"
    local f
    for f in "${FAIL_LOG[@]}"; do printf "  • %s\n" "$f"; done
    return 1
  fi
  return 0
}

# ── prerequisite checks ────────────────────────────────────────────────────

require_command() {
  for cmd in "$@"; do
    if ! command -v "$cmd" &>/dev/null; then
      printf "%s✗%s required command not found: %s\n" "$C_RED" "$C_RESET" "$cmd" >&2
      exit 2
    fi
  done
}

require_env() {
  for var in "$@"; do
    if [[ -z "${!var:-}" ]]; then
      printf "%s✗%s required env var not set: %s\n" "$C_RED" "$C_RESET" "$var" >&2
      exit 2
    fi
  done
}

# resolve_jwt_secret — return JWT_SECRET in priority order:
#   1. $JWT_SECRET env (CI sets this from a GitHub secret)
#   2. $VSP_JWT_SECRET_FILE if file is readable without sudo
#   3. /etc/vsp/env.production with sudo (local dev/operator path)
#
# Echoes the secret to stdout. Caller does:
#   JWT_SECRET=$(resolve_jwt_secret) || exit 2
#
# Designed so the same scripts work in three contexts:
#   - GitHub Actions (env set)
#   - Operator's laptop (sudo + canonical file path)
#   - Hermetic test rig (a custom file path with no sudo needed)
resolve_jwt_secret() {
  if [[ -n "${JWT_SECRET:-}" ]]; then
    printf '%s' "$JWT_SECRET"
    return 0
  fi
  local f="${VSP_JWT_SECRET_FILE:-/etc/vsp/env.production}"
  # Try without sudo first (works in CI when secret is mounted as a
  # plain file, or when running as root).
  if [[ -r "$f" ]]; then
    grep '^JWT_SECRET=' "$f" 2>/dev/null | cut -d= -f2- | head -1
    return 0
  fi
  # Fall back to sudo (operator path on a host where the file is
  # 0600 root). If sudo isn't available or prompts, this fails fast.
  if command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
    sudo grep '^JWT_SECRET=' "$f" 2>/dev/null | cut -d= -f2- | head -1
    return 0
  fi
  return 1
}
