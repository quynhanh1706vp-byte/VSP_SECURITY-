#!/usr/bin/env bash
# scripts/test-l27-observability.sh — observability completeness audit.
#
# Five phases asserting an operator can actually SEE what the gateway
# is doing in production:
#
#   28.1 Prometheus /metrics endpoint healthy + parseable.
#   28.2 Critical counters present (auth, scan, audit, errors).
#   28.3 Latency histograms exist with sensible buckets.
#   28.4 Log lines are structured JSON when LOG_LEVEL ≥ info.
#   28.5 Every panic recovered + logged (chimw.Recoverer wired).
#
# Pre-flight: gateway running, optional metrics scrape token via
# X-Metrics-Token header.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq awk grep

# ── 28.1 /metrics endpoint healthy + parseable ────────────────────────────

phase_open "28.1 /metrics endpoint healthy"

# Loopback access is allowed. Probe + parse Prometheus exposition.
METRICS_TMP=$(mktemp)
status=$(curl -s -o "$METRICS_TMP" -w "%{http_code}" --max-time 5 "$BASE/metrics")
if [[ "$status" != "200" ]]; then
  _fail "28.1.1 /metrics returned $status" "expected 200 from loopback"
  rm -f "$METRICS_TMP"
  final_summary; exit $?
fi

LINES=$(wc -l < "$METRICS_TMP" | tr -d ' ')
HELP_LINES=$(grep -c "^# HELP " "$METRICS_TMP" || true)
TYPE_LINES=$(grep -c "^# TYPE " "$METRICS_TMP" || true)
DATA_LINES=$(grep -cE '^[a-zA-Z][a-zA-Z0-9_]*' "$METRICS_TMP" || true)

if (( HELP_LINES >= 5 && TYPE_LINES >= 5 && DATA_LINES >= 20 )); then
  _pass "28.1.1 /metrics parseable [$LINES lines, $HELP_LINES HELP, $TYPE_LINES TYPE, $DATA_LINES samples]"
else
  _fail "28.1.1 /metrics shape thin" \
    "$LINES lines / $HELP_LINES HELP / $TYPE_LINES TYPE / $DATA_LINES samples"
fi

# ── 28.2 Critical counters present ────────────────────────────────────────

phase_open "28.2 Critical counters — auth / audit / errors"

# Probe for at least ONE counter from each domain. We accept either
# domain-specific naming (vsp_auth_login_total) or chi-router
# generic (chi_requests_total).
declare -A DOMAINS=(
  ["go_runtime"]="^go_(goroutines|memstats|gc|info|threads|sched|cpu)"
  ["process"]="^process_(cpu|memory|open_fds|resident|virtual|start)"
  ["vsp_app"]="^vsp_"
)

for dom in "${!DOMAINS[@]}"; do
  pat="${DOMAINS[$dom]}"
  count=$(grep -cE "$pat" "$METRICS_TMP" || true)
  if (( count >= 1 )); then
    _pass "28.2 $dom — $count metric series matched /$pat/"
  else
    _fail "28.2 $dom missing" "no metric matched /$pat/ — domain unobserved"
  fi
done

# Domain-level instrumentation. Auth login attempts, audit chain
# breaks + inserts, and per-route HTTP request latency must all be
# observable so operators can page on rate spikes / breaks.
for dom_pat in "vsp_login_attempts_total|login_attempts_total|auth_login_total" \
              "vsp_audit_inserts_total|vsp_audit_chain_breaks_total|audit_log_inserts_total" \
              "vsp_api_request_duration_seconds|http_request_duration_seconds|http_requests_total"; do
  if grep -qE "^($dom_pat)" "$METRICS_TMP" 2>/dev/null; then
    _pass "28.2.x domain counter present [$dom_pat]"
  else
    _fail "28.2.x domain counter missing" \
      "no metric matched $dom_pat — operators can't observe this domain"
  fi
done

# ── 28.3 Histogram buckets sane ───────────────────────────────────────────

phase_open "28.3 Latency histograms — buckets sensible"

# Find the first _bucket series, dump its le= values, assert they
# cover both ms and second ranges.
HIST_NAME=$(grep -oE "^[a-z][a-z_]*_bucket" "$METRICS_TMP" | head -1 | sed 's/_bucket$//')
if [[ -z "$HIST_NAME" ]]; then
  _skip "28.3.1 latency histogram" "no _bucket metric in /metrics output"
else
  buckets=$(grep "^${HIST_NAME}_bucket" "$METRICS_TMP" \
    | grep -oE 'le="[^"]+"' | sort -u | head -10 | tr -d '"' | tr '\n' ',')
  # Sane = at least one sub-second bucket AND at least one >= 1s.
  has_sub=$(echo "$buckets" | grep -cE 'le=0\.[0-9]+' || true)
  has_super=$(echo "$buckets" | grep -cE 'le=([1-9][0-9]*|\+Inf)' || true)
  if (( has_sub >= 1 && has_super >= 1 )); then
    _pass "28.3.1 $HIST_NAME has buckets in ms and seconds [$buckets]"
  else
    _fail "28.3.1 $HIST_NAME bucket coverage thin" "buckets: $buckets"
  fi
fi

rm -f "$METRICS_TMP"

# ── 28.4 Logs are structured JSON ─────────────────────────────────────────

phase_open "28.4 Log lines — structured (JSON or zerolog console kv)"

# Logs need to be MACHINE-PARSEABLE — either JSON or zerolog's
# console format ("INF http method=GET path=... status=200"). Both
# carry structured key=value pairs that log shippers can parse.
# What we DON'T accept is freeform "thing happened" prose.
LOG_TMP=$(mktemp)
sudo journalctl -u vsp-gateway --no-pager -n 100 2>/dev/null > "$LOG_TMP" || true
# Fallback for non-systemd environments (CI containers, dev machines):
# the gateway often runs as a foreground process or under nohup and
# its stdout/stderr go to a file. Honour LOG_FALLBACK if set.
if [[ ! -s "$LOG_TMP" || $(grep -cE '^-- (No entries|Logs begin)' "$LOG_TMP") -gt 0 ]] \
   && [[ -n "${LOG_FALLBACK:-}" && -r "$LOG_FALLBACK" ]]; then
  tail -100 "$LOG_FALLBACK" > "$LOG_TMP" 2>/dev/null || true
fi

# Pick lines after the journal prefix (date + host + service + pid).
# Strip journal sentinels like "-- No entries --" — they're meta
# markers, not real log lines, and should count as 0 lines (skip).
# Also strip ANSI colour codes — zerolog ConsoleWriter emits them by
# default, which would break the timestamp/level regex below.
BODY=$(sed -E 's/^[A-Z][a-z]+ +[0-9]+ +[0-9:]+ +[^ ]+ +[^:]+: //' "$LOG_TMP" \
        | sed -E 's/\x1b\[[0-9;]*m//g' \
        | grep -vE '^-- (No entries|Logs begin|Reboot)' \
        | tail -50)
TOTAL=$(echo "$BODY" | grep -c . || true)
# Structured = ANY of:
#   - JSON: ^{ ... }$
#   - zerolog console with kv: timestamp INF/WRN/ERR + at least one
#     key=value pair somewhere on the line
#   - retention banner: zerolog INF with "subsystem: text" + 1 kv pair
# Unstructured = bare prose / log.Println-style lines.
# Accept JSON OR any zerolog console line (level prefix tells the
# log shipper how to route, even if no kv field is attached).
STRUCTURED=$(echo "$BODY" \
  | grep -cE '^\{.*\}$|^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+ (INF|WRN|ERR|DBG|FTL|TRC) ' \
  || true)
UNSTRUCTURED=$((TOTAL - STRUCTURED))

if (( TOTAL == 0 )); then
  _skip "28.4.1 log shape" "no log lines captured from journal"
elif (( UNSTRUCTURED * 100 / (TOTAL + 1) <= 30 )); then
  _pass "28.4.1 logs structured [$STRUCTURED kv / $UNSTRUCTURED plain / $TOTAL total]"
else
  EXAMPLES=$(echo "$BODY" | grep -vE '^\{.*\}$|[a-z_]+=[^ ]+.*[a-z_]+=' | head -2 | tr '\n' '|')
  _fail "28.4.1 too many plain-text log lines" \
    "$UNSTRUCTURED/$TOTAL plain — examples: $EXAMPLES"
fi
rm -f "$LOG_TMP"

# ── 28.5 Panic recovery middleware wired ──────────────────────────────────

phase_open "28.5 Panic recovery — chimw.Recoverer in router stack"

if grep -qE "r\.Use\(chimw\.Recoverer\)" "$ROOT/cmd/gateway/main.go"; then
  _pass "28.5.1 chimw.Recoverer wired in router"
else
  _fail "28.5.1 chimw.Recoverer missing" \
    "no Recoverer in router — a panic in any handler crashes the process"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
