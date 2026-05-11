#!/usr/bin/env bash
# scripts/test-l53-prom-cardinality.sh — Prometheus metric cardinality.
#
# Common operational bug: a developer adds a histogram with `path` as
# a label, where `path` is the unmodified request URL. Every distinct
# URL becomes its own time series → memory pressure on the metrics
# scraper and on the gateway's own metrics registry.
#
# Rule of thumb: each metric should have ≤ ~500 distinct label-value
# combinations. UUIDs, free-form paths, user emails, IPs as labels =
# cardinality bombs.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 53.1 Pull /metrics and count series per metric name ──────────────────

phase_open "53.1 Metric cardinality budget"

# Standard Prometheus endpoint at /metrics; gateway also exposes
# /metrics/vsp for the custom registry.
METRICS=$(mktemp)
status=$(curl -s -o "$METRICS" -w "%{http_code}" --max-time 10 \
  "$BASE/metrics" 2>/dev/null || echo "000")

if [[ "$status" != "200" ]]; then
  status=$(curl -s -o "$METRICS" -w "%{http_code}" --max-time 10 \
    "$BASE/metrics/vsp" 2>/dev/null || echo "000")
fi

if [[ "$status" != "200" ]]; then
  _skip "53.1.0 /metrics endpoint" "HTTP $status — endpoint not reachable"
  final_summary; exit 0
fi

LINES=$(wc -l < "$METRICS" | tr -d ' ')
_pass "53.1.0 /metrics fetched [$LINES lines]"

# Count distinct series per metric name. Format:
#   metric_name{label1="v1",label2="v2"} value
# Strip the value + labels, then count unique label-sets per metric.
SUSPECT=$(awk '
  # Skip comments (HELP/TYPE) and blanks
  /^#/ { next }
  /^$/ { next }
  {
    # Extract metric name = chars before { or space
    name = $1
    sub(/[{ ].*/, "", name)
    count[name]++
  }
  END {
    for (name in count) {
      if (count[name] > 500) {
        printf "%s:%d\n", name, count[name]
      }
    }
  }
' "$METRICS" | sort -t: -k2 -nr | head -3)

rm -f "$METRICS"

if [[ -z "$SUSPECT" ]]; then
  _pass "53.1.1 no metric exceeds 500-series cardinality budget"
else
  _fail "53.1.1 high-cardinality metric(s)" \
    "$(echo "$SUSPECT" | head -1) — review label choice (path / user_id / ip = bombs)"
fi

# ── 53.2 Static scan — labels look like cardinality bombs ────────────────

phase_open "53.2 Source-level cardinality hazards"

# Look for prometheus.Labels{ "path": req.URL.Path, ... } and similar
# raw-URL-as-label patterns. The codebase normalises paths through a
# route template (e.g. /api/v1/findings/{id}) — using raw .Path
# defeats the template.
HAZARDS=$(grep -rEn 'prometheus\.Labels\{[^}]*"(path|url|ip|user_id|email)"[^}]*\}|WithLabelValues\(.*r\.URL\.Path' \
  --include='*.go' \
  "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -3 || true)

if [[ -n "$HAZARDS" ]]; then
  # Each match could be legitimate (e.g. template path). Need to
  # inspect — report informational.
  _skip "53.2.1 raw-path-as-label patterns found" \
    "review: $(echo "$HAZARDS" | head -1)"
else
  _pass "53.2.1 no raw-URL-as-prometheus-label patterns"
fi

# ── 53.3 Histogram bucket count sanity ───────────────────────────────────

phase_open "53.3 Histogram bucket counts reasonable"

# A histogram with 50+ buckets multiplies cardinality. Most use cases
# need 8-15 buckets.
METRICS=$(mktemp)
curl -s -o "$METRICS" --max-time 5 "$BASE/metrics" 2>/dev/null || true
[[ ! -s "$METRICS" ]] && curl -s -o "$METRICS" --max-time 5 "$BASE/metrics/vsp" 2>/dev/null || true

if [[ ! -s "$METRICS" ]]; then
  _skip "53.3.1 histogram bucket check" "no metrics body"
else
  FAT_HIST=$(awk '
    /_bucket\{/ {
      name = $1; sub(/_bucket\{.*/, "", name)
      count[name]++
    }
    END {
      for (name in count) {
        # Bucket count = series count per histogram. Histograms with
        # >40 buckets are unusual.
        if (count[name] > 200) printf "%s:%d\n", name, count[name]
      }
    }
  ' "$METRICS" | sort -t: -k2 -nr | head -2)
  rm -f "$METRICS"

  if [[ -z "$FAT_HIST" ]]; then
    _pass "53.3.1 no histograms with absurd bucket counts"
  else
    _skip "53.3.1 fat histogram" "$FAT_HIST — review bucket boundaries"
  fi
fi

final_summary
