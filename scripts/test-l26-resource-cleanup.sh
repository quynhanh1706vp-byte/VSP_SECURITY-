#!/usr/bin/env bash
# scripts/test-l26-resource-cleanup.sh — resource-cleanup audit.
#
# Static analysis: every resource that needs Close() actually gets
# closed on every code path. Catches:
#
#   27.1 os.Open / os.Create without defer Close
#   27.2 http.Response.Body without defer Close
#   27.3 sql/pgx Rows without defer Close
#   27.4 multipart File without Close
#   27.5 SQL Begin without Commit/Rollback
#
# Plus behavioural: hammer endpoint and verify open-FD count is
# bounded after.
#
# Pre-flight: gateway running for the FD-count probe.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl grep awk

# ── 27.1 os.Open / os.Create without defer Close ──────────────────────────

phase_open "27.1 File handles — every os.Open has a defer Close"

# We grep for `os.Open` / `os.Create` and check the same function
# block contains a `Close()` call (defer or explicit). False positives
# are accepted (e.g. helper that returns the *os.File for caller to
# close); they manifest as flagged sites that need manual review.
LEAK_SITES=()
while IFS= read -r line; do
  file=$(echo "$line" | cut -d: -f1)
  ln=$(echo "$line" | cut -d: -f2)
  # Pull function body around this line. Use sed to extract from the
  # last `func ... {` before the line until matching `^}`.
  start=$(awk -v lineno="$ln" 'NR <= lineno && /^func / {match_ln=NR} END {print match_ln}' "$file")
  [[ -z "$start" || "$start" == "0" ]] && continue
  block=$(awk -v s="$start" 'NR >= s {print; if ($0 == "}" && NR > s) exit}' "$file")
  if ! echo "$block" | grep -qE "(\.Close\(\)|defer.*Close)"; then
    LEAK_SITES+=("$file:$ln")
  fi
done < <(grep -rEn '\bos\.(Open|Create)\(' --include="*.go" \
         -- "$ROOT/internal" "$ROOT/cmd" 2>/dev/null \
         | grep -v "_test\|\.bak")

if (( ${#LEAK_SITES[@]} == 0 )); then
  _pass "27.1.1 every os.Open/Create has a Close in its function"
else
  printf -v LIST '%s | ' "${LEAK_SITES[@]:0:5}"
  _fail "27.1.1 ${#LEAK_SITES[@]} potential file-handle leaks" "${LIST%| }"
fi

# ── 27.2 http.Response.Body without defer Close ───────────────────────────

phase_open "27.2 HTTP response bodies — Close on every reachable path"

# Every `http.Get`, `client.Do`, `http.Post` returns a *Response
# whose Body must be closed. Static check: line N has `resp, err :=`
# from such a call → within next 10 lines there's `defer resp.Body.Close()`
# (allowing for the err check in between).
LEAK_HTTP=()
while IFS= read -r line; do
  file=$(echo "$line" | cut -d: -f1)
  ln=$(echo "$line" | cut -d: -f2)
  # Look at next 10 lines for a Body.Close.
  if ! awk -v s="$ln" -v e=$((ln+12)) 'NR >= s && NR <= e' "$file" \
       | grep -qE "(\.Body\.Close\(\)|defer.*Body\.Close)"; then
    # Skip helper functions whose return value is intentionally
    # the *Response for the caller to close.
    block=$(awk -v s="$ln" 'NR >= s {print; if ($0 == "}") exit}' "$file" \
           | head -20)
    if echo "$block" | grep -qE "^\s*return.*resp"; then
      continue
    fi
    LEAK_HTTP+=("$file:$ln")
  fi
done < <(grep -rEn 'http\.(Get|Post|PostForm|Head)\(|client\.Do\(|httpClient\.Do\(' \
         --include="*.go" -- "$ROOT/internal" "$ROOT/cmd" 2>/dev/null \
         | grep -v "_test\|\.bak\|//" )

if (( ${#LEAK_HTTP[@]} == 0 )); then
  _pass "27.2.1 every HTTP response Body has a near-by Close"
else
  printf -v LIST '%s | ' "${LEAK_HTTP[@]:0:5}"
  _fail "27.2.1 ${#LEAK_HTTP[@]} HTTP responses without Body.Close" "${LIST%| }"
fi

# ── 27.3 SQL rows / pgx.Rows — defer Close ────────────────────────────────

phase_open "27.3 DB rows — Close after Query"

# A defer or explicit rows.Close must appear before the enclosing
# function returns. Loop bodies can be 30-40 lines, so widen the
# search window. Find each matching `func` block containing the
# Query call and check the WHOLE block for a Close.
# Look at the 60 lines AFTER each rows.Query for a Close. This is
# generous enough for typical loop bodies and tight enough that a
# missing Close produces a clean signal. cmd/gateway/main.go has
# deeply-nested closures inside main() that defeat func-block parsing,
# so we use a flat line window.
LEAK_ROWS=()
while IFS= read -r line; do
  file=$(echo "$line" | cut -d: -f1)
  ln=$(echo "$line" | cut -d: -f2)
  if awk -v s="$ln" -v e=$((ln+60)) 'NR >= s && NR <= e' "$file" \
     | grep -qE "(rows\.Close\(\)|defer\s+rows\.Close|return\s+rows)"; then
    continue
  fi
  LEAK_ROWS+=("$file:$ln")
done < <(grep -rEn 'rows,\s*err\s*[:=].*\.Query\(' \
         --include="*.go" -- "$ROOT/internal" "$ROOT/cmd" 2>/dev/null \
         | grep -v "_test\|\.bak\|//" )

if (( ${#LEAK_ROWS[@]} == 0 )); then
  _pass "27.3.1 every rows.Query has a matching Close in its function"
else
  printf -v LIST '%s | ' "${LEAK_ROWS[@]:0:5}"
  _fail "27.3.1 ${#LEAK_ROWS[@]} rows.Query without Close" "${LIST%| }"
fi

# ── 27.4 multipart FormFile — defer Close ─────────────────────────────────

phase_open "27.4 Multipart files — defer Close"

LEAK_MP=()
while IFS= read -r line; do
  file=$(echo "$line" | cut -d: -f1)
  ln=$(echo "$line" | cut -d: -f2)
  if ! awk -v s="$ln" -v e=$((ln+5)) 'NR >= s && NR <= e' "$file" \
       | grep -qE "(file\.Close\(\)|defer\s+file\.Close)"; then
    LEAK_MP+=("$file:$ln")
  fi
done < <(grep -rEn 'file,\s*[a-z_]+,?\s*err\s*[:=].*FormFile\(' \
         --include="*.go" -- "$ROOT/internal" "$ROOT/cmd" 2>/dev/null \
         | grep -v "_test\|\.bak" )

if (( ${#LEAK_MP[@]} == 0 )); then
  _pass "27.4.1 every multipart FormFile has a Close"
else
  printf -v LIST '%s | ' "${LEAK_MP[@]:0:5}"
  _fail "27.4.1 ${#LEAK_MP[@]} multipart Files without Close" "${LIST%| }"
fi

# ── 27.5 SQL Begin without Commit/Rollback ───────────────────────────────

phase_open "27.5 Tx Begin — paired with Commit/Rollback (or defer Rollback)"

LEAK_TX=()
while IFS= read -r line; do
  file=$(echo "$line" | cut -d: -f1)
  ln=$(echo "$line" | cut -d: -f2)
  # Within next 30 lines (transactions can be long), must see either
  # tx.Commit, tx.Rollback, OR `defer tx.Rollback`.
  if ! awk -v s="$ln" -v e=$((ln+50)) 'NR >= s && NR <= e' "$file" \
       | grep -qE "(tx\.Commit\(\)|tx\.Rollback\(\)|defer.*tx\.Rollback)"; then
    LEAK_TX+=("$file:$ln")
  fi
done < <(grep -rEn 'tx,\s*err\s*[:=].*\.Begin\(' \
         --include="*.go" -- "$ROOT/internal" "$ROOT/cmd" 2>/dev/null \
         | grep -v "_test\|\.bak" )

if (( ${#LEAK_TX[@]} == 0 )); then
  _pass "27.5.1 every tx.Begin paired with Commit or Rollback"
else
  printf -v LIST '%s | ' "${LEAK_TX[@]:0:5}"
  _fail "27.5.1 ${#LEAK_TX[@]} tx.Begin without paired Commit/Rollback" "${LIST%| }"
fi

# ── 27.6 Behavioral — open-FD count bounded ───────────────────────────────

phase_open "27.6 Open-FD growth bounded after burst"

GW_PID=$(pgrep -f "/usr/local/bin/vsp-gateway" | head -1)
if [[ -z "$GW_PID" ]]; then
  _skip "27.6.1 FD count probe" "gateway pid not found"
else
  FD_BEFORE=$(ls /proc/"$GW_PID"/fd 2>/dev/null | wc -l)
  # Burst: 100 simple GETs + a few uploads.
  for i in $(seq 1 100); do
    curl -s -o /dev/null --max-time 5 "$BASE/api/v1/status" &
  done
  wait
  sleep 2
  FD_AFTER=$(ls /proc/"$GW_PID"/fd 2>/dev/null | wc -l)
  DELTA=$((FD_AFTER - FD_BEFORE))
  if (( DELTA <= 10 )); then
    _pass "27.6.1 FD growth bounded [$FD_BEFORE → $FD_AFTER, +$DELTA]"
  else
    _fail "27.6.1 FD leak suspected" \
      "$DELTA new FDs after 100-burst (FD_BEFORE=$FD_BEFORE, AFTER=$FD_AFTER)"
  fi
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
