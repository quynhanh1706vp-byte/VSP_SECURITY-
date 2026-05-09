#!/usr/bin/env bash
# scripts/test-l10-openapi.sh — OpenAPI live conformance.
#
# For every GET endpoint documented in api/openapi.yaml that's safe to
# call against a running gateway, hit it with an admin token and assert:
#
#   11.1 GET routes documented in spec actually exist (200/2xx, not 404)
#   11.2 GET routes responding with 200 emit application/json
#        (the spec implies application/json across the board)
#   11.3 Surface drift: every GET route in cmd/gateway/main.go that
#        touches /api/v1 SHOULD also be in the spec. Routes in code
#        but missing from spec are either accidentally-public or
#        documentation drift.
#
# We deliberately scope to GET to keep this idempotent — POST/PUT
# probes belong in L9 lifecycle. Admin-only endpoints get the admin
# token; other endpoints get a tenant admin token too (same auth).
#
# Pre-flight: $DB_DSN, $JWT_SECRET, gateway running, jq + python3 (PyYAML).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq python3

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

mint_jwt() {
  local now exp header payload sig
  now=$(date +%s); exp=$((now + 3600))
  header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  payload=$(printf '{"sub":"l10@vsp.local","email":"l10@vsp.local","role":"admin","tenant_id":"default","iat":%d,"exp":%d}' \
    "$now" "$exp" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  sig=$(printf '%s' "$header.$payload" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  printf '%s.%s.%s\n' "$header" "$payload" "$sig"
}

ADMIN=$(mint_jwt)

# ── parse spec → extract { path, method } pairs into a JSON file ────────────

SPEC="$ROOT/api/openapi.yaml"
if [[ ! -f "$SPEC" ]]; then
  printf "%s✗%s api/openapi.yaml missing\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

PARSED=$(mktemp)
python3 - "$SPEC" > "$PARSED" <<'PY'
import sys, yaml, json
with open(sys.argv[1]) as f:
    spec = yaml.safe_load(f)
out = []
for path, item in (spec.get("paths") or {}).items():
    if not path.startswith("/api/v1"):
        continue
    for method in ("get", "post", "put", "patch", "delete"):
        if method in item:
            op_id = item[method].get("operationId", "")
            tags = item[method].get("tags", [])
            out.append({
                "path": path,
                "method": method.upper(),
                "operation_id": op_id,
                "tags": tags,
            })
print(json.dumps(out))
PY

SPEC_GET_PATHS=$(jq -r '.[] | select(.method == "GET") | .path' "$PARSED" | sort -u)

# ── 11.1 Documented GET endpoints actually exist ───────────────────────────

phase_open "11.1 Documented GET endpoints — exist (no 404)"

# Substitute path parameters {id}, {rid} etc. with test fixtures
# resolved from the DB so probes don't hit "invalid uuid" 400s. We
# pick the first usable row per resource — it just has to be parseable.
RUN_RID=$(_psql_oneshot "SELECT rid FROM runs ORDER BY created_at DESC LIMIT 1;")
RUN_UUID=$(_psql_oneshot "SELECT id FROM runs ORDER BY created_at DESC LIMIT 1;")
USER_UUID=$(_psql_oneshot "SELECT id FROM users WHERE role='admin' LIMIT 1;")
TENANT_UUID=$(_psql_oneshot "SELECT id FROM tenants WHERE slug='default' LIMIT 1;")
EVID_UUID=$(_psql_oneshot "SELECT id FROM compliance_evidence LIMIT 1;")
DSR_UUID=$(_psql_oneshot "SELECT id FROM data_subject_requests LIMIT 1;")

substitute_path() {
  local p="$1"
  p="${p//\{rid\}/$RUN_RID}"
  p="${p//\{id\}/$RUN_UUID}"
  p="${p//\{user_id\}/$USER_UUID}"
  p="${p//\{tenant_id\}/$TENANT_UUID}"
  p="${p//\{evidence_id\}/$EVID_UUID}"
  p="${p//\{request_id\}/$DSR_UUID}"
  p="${p//\{uuid\}/$RUN_UUID}"
  p="${p//\{cacheKey\}/probe}"
  p="${p//\{repoID\}/probe}"
  p="${p//\{finding_id\}/$RUN_UUID}"
  p="${p//\{batch_id\}/$RUN_UUID}"
  printf '%s' "$p"
}

# Track which spec paths PASSED so we can summarize.
declare -a SPEC_404 SPEC_500 SPEC_OK
PROBE_TOTAL=0
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  resolved=$(substitute_path "$path")
  # If a placeholder is still in the path (no fixture available), skip.
  if [[ "$resolved" == *"{"*"}"* ]]; then
    _skip "11.1 GET $path" "no fixture for path placeholder ($resolved)"
    continue
  fi
  PROBE_TOTAL=$((PROBE_TOTAL+1))
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" "$BASE$resolved")
  if [[ "$status" =~ ^(200|204|404)$ ]]; then
    # 404 here is acceptable for ID-bearing routes when the fixture
    # row truly doesn't exist for the caller; the route itself was
    # found by chi. What we really want to flag is 5xx (handler bug)
    # or routing-level errors. Distinguish the no-route 404 from
    # resource-404 by also checking the error text isn't "404 page
    # not found".
    if [[ "$status" == "404" ]]; then
      body=$(curl -s --max-time 5 -H "Authorization: Bearer $ADMIN" "$BASE$resolved" | head -c 100)
      if [[ "$body" == "404 page not found" ]]; then
        SPEC_404+=("$path")
        _fail "11.1 GET $path" "route not mounted in gateway (chi 404)"
        continue
      fi
    fi
    SPEC_OK+=("$path")
    _pass "11.1 GET $path [$status]"
  elif [[ "$status" =~ ^5 ]]; then
    SPEC_500+=("$path[$status]")
    _fail "11.1 GET $path" "HTTP $status — handler error"
  else
    # 401/403/400 — auth or input issue, treat as found.
    SPEC_OK+=("$path")
    _pass "11.1 GET $path [$status non-2xx but routed]"
  fi
done <<<"$SPEC_GET_PATHS"

# ── 11.2 200 responses are application/json ────────────────────────────────

phase_open "11.2 GET 200 responses are application/json"

NON_JSON=()
for path in "${SPEC_OK[@]}"; do
  # SSE / event streams are deliberately not JSON.
  case "$path" in
    *"/events"|*"/sse"|*"/stream"|*"/tail") continue ;;
  esac
  resolved=$(substitute_path "$path")
  ct=$(curl -s -o /dev/null -w "%{content_type}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" "$BASE$resolved")
  if [[ "$ct" == application/json* || "$ct" == "" ]]; then
    : # ok
  else
    NON_JSON+=("$path[$ct]")
  fi
done
if (( ${#NON_JSON[@]} == 0 )); then
  _pass "11.2.1 every probed GET returns application/json (or empty)"
else
  printf -v NLIST '%s, ' "${NON_JSON[@]:0:5}"
  _fail "11.2.1 non-JSON content-type" "${#NON_JSON[@]} routes: ${NLIST%, }"
fi

# ── 11.3 Surface drift: undocumented GETs ──────────────────────────────────

phase_open "11.3 Surface drift — GETs in code missing from spec"

# Extract every `r.Get("/api/v1/...")` from cmd/gateway/main.go.
GATEWAY_GETS=$(grep -E 'r\.Get\("/api/v1/' "$ROOT/cmd/gateway/main.go" 2>/dev/null \
  | grep -v "//\|\.bak" \
  | grep -oE '"/api/v1/[^"]*"' | tr -d '"' | sort -u)

declare -A IN_SPEC
while IFS= read -r p; do
  IN_SPEC["$p"]=1
done <<<"$SPEC_GET_PATHS"

UNDOC=()
DOC_COUNT=0
TOTAL_CODE=0
while IFS= read -r p; do
  [[ -z "$p" ]] && continue
  TOTAL_CODE=$((TOTAL_CODE+1))
  # Normalize chi {param} to spec-style {param} (already same).
  if [[ -z "${IN_SPEC[$p]:-}" ]]; then
    # Some endpoints are intentionally undocumented (internal /metrics,
    # SSE streams, p4 bridge). Filter those.
    case "$p" in
      *"/healthz"|*"/metrics"|*"/sse"|*"/events"|*"/tail"|*"/log"|"/api/v1/p4/"*|"/api/v1/internal/"*)
        continue ;;
    esac
    UNDOC+=("$p")
  else
    DOC_COUNT=$((DOC_COUNT+1))
  fi
done <<<"$GATEWAY_GETS"

# Ratchet: lock the currently-undocumented count. New PRs that add
# undocumented endpoints push above the baseline and fail; PRs that
# document existing endpoints lower the baseline as part of the same
# commit. This avoids one giant doc-sprint while still locking in
# every gain. Update RATCHET when you intentionally accept a higher
# count or close out documented endpoints.
RATCHET=142
COUNT=${#UNDOC[@]}
if (( COUNT == 0 )); then
  _pass "11.3.1 every public GET is documented [$DOC_COUNT/$TOTAL_CODE]"
elif (( COUNT < RATCHET )); then
  _pass "11.3.1 OpenAPI doc-drift below ratchet [$COUNT/$RATCHET — lower the ratchet in this PR]"
elif (( COUNT == RATCHET )); then
  _pass "11.3.1 OpenAPI doc-drift at ratchet [$COUNT/$RATCHET — no regression]"
else
  printf -v ULIST '%s, ' "${UNDOC[@]:0:8}"
  _fail "11.3.1 ${COUNT} GET(s) > ratchet ${RATCHET}" \
    "${COUNT} undocumented vs baseline ${RATCHET} — new endpoints added without OpenAPI entries: ${ULIST%, }"
fi

rm -f "$PARSED"

# ── final ──────────────────────────────────────────────────────────────────

final_summary
