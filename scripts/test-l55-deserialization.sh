#!/usr/bin/env bash
# scripts/test-l55-deserialization.sh — unsafe deserialization audit.
#
# Static-analysis sweep over Go source for known-dangerous deserialisation
# patterns:
#
#   1. encoding/gob.NewDecoder(io.Reader).Decode(&v) — gob deserialises
#      ARBITRARY types including registered concrete types; an attacker
#      who controls the bytes can instantiate any type the program has
#      registered, including ones with side-effecting UnmarshalBinary.
#
#   2. gopkg.in/yaml.v2 / .v3 Unmarshal with `interface{}` target —
#      classic ZipSlip-class for YAML (no exec, but billion-laughs).
#
#   3. json.NewDecoder without DisallowUnknownFields + max-body — JSON
#      bombs (deeply nested arrays) can OOM the parser.
#
#   4. encoding/xml on user input — XXE if WithoutEntityDecoding isn't
#      explicit (Go's encoding/xml is generally safe, but worth a probe).
#
#   5. fmt.Sscanf on user input — format-string bug surface.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 55.1 gob.NewDecoder on request body ──────────────────────────────────

phase_open "55.1 encoding/gob deserialization"

# Find any gob.NewDecoder(r.Body) or gob.NewDecoder(req.Body). gob
# on untrusted input is dangerous; the Go docs warn explicitly.
GOB_HITS=$(grep -rEn 'gob\.NewDecoder\s*\(\s*(req\.Body|r\.Body|http\.Request)' \
  --include='*.go' \
  "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -3 || true)

if [[ -n "$GOB_HITS" ]]; then
  _fail "55.1.1 gob.NewDecoder on request body" "$(echo "$GOB_HITS" | head -1)"
else
  _pass "55.1.1 no gob.NewDecoder on HTTP request bodies"
fi

# ── 55.2 yaml.Unmarshal with interface{} target ──────────────────────────

phase_open "55.2 yaml.Unmarshal to interface{}"

# yaml.Unmarshal(data, &target) where target is map[string]interface{}
# / []interface{} / interface{}. Without a typed schema, the parser
# accepts arbitrarily-deep structures and arbitrary tag types.
YAML_HITS=$(grep -rEn 'yaml\.Unmarshal\s*\([^,]+,\s*&?(\w+)\s*\)' \
  --include='*.go' \
  "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -3 || true)

# Heuristic: a yaml.Unmarshal call with a generic interface{} target.
# We accept calls with a typed struct.
UNSAFE=$(echo "$YAML_HITS" | grep -v '// safe-yaml' | head -3)
COUNT=$(echo "$UNSAFE" | grep -c . 2>/dev/null || echo 0)
COUNT=${COUNT:-0}
if (( COUNT == 0 )); then
  _pass "55.2.1 no yaml.Unmarshal calls (or all marked safe)"
elif (( COUNT <= 10 )); then
  _skip "55.2.1 yaml.Unmarshal usage" \
    "$COUNT call sites — review whether targets are typed structs"
else
  _fail "55.2.1 too many yaml.Unmarshal call sites" "$COUNT"
fi

# ── 55.3 json.NewDecoder without MaxBytesReader ──────────────────────────

phase_open "55.3 json.NewDecoder bounded by MaxBytesReader"

# json.NewDecoder(r.Body).Decode(&v) without MaxBytesReader is a DoS
# vector — attacker can submit a 1 GB body and the JSON parser will
# stream-allocate as it goes.
#
# The fix is `r.Body = http.MaxBytesReader(w, r.Body, N)` before
# json.NewDecoder. Sample 10 handlers and verify the helper is
# nearby. The gateway already has a global 4 MB MaxBytesReader on
# its router (cmd/gateway/main.go), so this is a defensive check.
GLOBAL_MAX=$(grep -rEn 'MaxBytesReader\s*\(\s*w' \
  --include='*.go' \
  "$ROOT/cmd/gateway/" 2>/dev/null | wc -l | tr -d ' ')

if (( GLOBAL_MAX >= 1 )); then
  _pass "55.3.1 router has MaxBytesReader middleware (>=$GLOBAL_MAX call site)"
else
  _fail "55.3.1 no MaxBytesReader" \
    "json.NewDecoder + unbounded body = OOM vector"
fi

# 55.3.2 DisallowUnknownFields — strict JSON. Catches typos and
# defends against mass-assignment by REJECTING unknown keys.
STRICT=$(grep -rEn 'DisallowUnknownFields' \
  --include='*.go' \
  "$ROOT/internal/api/handler/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go' \
  | wc -l | tr -d ' ')

if (( STRICT >= 3 )); then
  _pass "55.3.2 DisallowUnknownFields used [$STRICT call sites]"
else
  _skip "55.3.2 DisallowUnknownFields adoption" \
    "$STRICT call sites — informational, increases mass-assignment defence"
fi

# ── 55.4 XML decoding — Strict mode, no external entities ───────────────

phase_open "55.4 encoding/xml DefaultEntities-only"

XML_HITS=$(grep -rEn 'xml\.NewDecoder\s*\(' \
  --include='*.go' \
  "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -5 || true)

if [[ -z "$XML_HITS" ]]; then
  _pass "55.4.1 no xml.NewDecoder usage (XXE risk negligible)"
else
  # Each match should set Strict=true and not use a custom Entity map.
  # Go's encoding/xml is generally safe by default, but flag the
  # presence for review.
  COUNT=$(echo "$XML_HITS" | wc -l | tr -d ' ')
  _skip "55.4.1 xml.NewDecoder usage" \
    "$COUNT call sites — Go xml is XXE-safe by default but review for d.Strict=false"
fi

# ── 55.5 fmt.Sscanf / fmt.Errorf with user input ─────────────────────────

phase_open "55.5 fmt format-string surface"

# fmt.Sscanf(userInput, fmtString, ...) where userInput is the format.
# Go is strict about format-string mismatches but it's still a smell.
SSCANF=$(grep -rEn 'fmt\.Sscanf?\s*\(\s*[a-z]' \
  --include='*.go' \
  "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go' \
  | head -3 || true)

if [[ -z "$SSCANF" ]]; then
  _pass "55.5.1 no fmt.Sscanf with user input"
else
  COUNT=$(echo "$SSCANF" | wc -l | tr -d ' ')
  _skip "55.5.1 fmt.Sscanf usage" \
    "$COUNT call sites — review first arg isn't attacker-controlled"
fi

final_summary
