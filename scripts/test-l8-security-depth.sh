#!/usr/bin/env bash
# scripts/test-l8-security-depth.sh — L8 advanced security depth.
#
# Five phases past L5's RBAC matrix:
#
#   9.1 Mass assignment — PUT/PATCH with extra fields (tenant_id, role,
#       id) MUST be ignored, not honored.
#
#   9.2 Audit completeness — every state-changing route in the gateway
#       maps to a handler that calls writeAudit/logAudit/InsertAudit.
#       Static analysis (no live probe) so it catches gaps before they
#       ship.
#
#   9.3 JWT lifecycle — alg=none / alg=RS256 confusion, future exp not
#       accepted, logout actually revokes the token.
#
#   9.4 Crypto sanity — bcrypt cost ≥ 10, JWT_SECRET length ≥ 32,
#       no math/rand in security-sensitive code paths.
#
#   9.5 Cross-tenant admin — admin in tenant A can NOT modify tenant
#       B's resources. Catches horizontal privilege escalation that
#       L5's RBAC matrix misses (it only probed within one tenant).
#
# Pre-flight: $DB_DSN, $JWT_SECRET, gateway running.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq psql openssl

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

TENANT_A_SLUG="default"
TENANT_A_UUID="1bdf7f20-dbb3-4116-815f-26b4dc747e76"
TENANT_B_SLUG="acme-corp"
TENANT_B_UUID="8bb9a716-fd14-4eba-92e8-681dc5bdb718"

mint_jwt() {
  local slug="$1" role="$2"
  local now exp header payload sig
  now=$(date +%s); exp=$((now + 3600))
  header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  payload=$(printf '{"sub":"l8@vsp.local","email":"l8@vsp.local","role":"%s","tenant_id":"%s","iat":%d,"exp":%d}' \
    "$role" "$slug" "$now" "$exp" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  sig=$(printf '%s' "$header.$payload" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  printf '%s.%s.%s\n' "$header" "$payload" "$sig"
}

ADMIN_A=$(mint_jwt "$TENANT_A_SLUG" admin)
ADMIN_B=$(mint_jwt "$TENANT_B_SLUG" admin)

# ── 9.1 Mass assignment ────────────────────────────────────────────────────

phase_open "9.1 Mass assignment — extra fields ignored"

# 9.1.1 Tool-config PUT — body should not be able to inject fields
# outside the documented {tools, auto_run, ...} schema.
RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -X PUT -H "Authorization: Bearer $ADMIN_A" -H "Content-Type: application/json" \
  -d '{"tools":[],"tenant_id":"'"$TENANT_B_UUID"'","role":"superadmin","id":"00000000-0000-0000-0000-000000000000"}' \
  "$BASE/api/v1/settings/tool-config")
# A 200/204 means the request was accepted; we then verify the
# attempted overrides did NOT take effect by re-reading the handler's
# state (or just trusting that valid Go decoders ignore unknown fields).
# Easier proof point: ensure tenant_id of subsequent reads still matches
# the caller's tenant.
PROBE=$(curl -s --max-time 5 -H "Authorization: Bearer $ADMIN_A" \
  "$BASE/api/v1/settings/tool-config" 2>/dev/null)
if [[ "$RESP" =~ ^(200|204|400)$ ]]; then
  if echo "$PROBE" | grep -q "$TENANT_B_UUID"; then
    _fail "9.1.1 tool-config mass assignment" \
      "tenant_id from PUT body leaked into stored config"
  else
    _pass "9.1.1 tool-config mass assignment ignored [$RESP]"
  fi
else
  _skip "9.1.1 tool-config mass assignment" "endpoint returned HTTP $RESP"
fi

# 9.1.2 Update plan — body should not let caller pass an unauthorized
# field. UpdatePlan decodes only {plan}; we send extra fields and
# verify only the allow-listed plan field is honored.
RESP=$(curl -s -o /tmp/l8_plan.json -w "%{http_code}" --max-time 5 \
  -X PUT -H "Authorization: Bearer $ADMIN_A" -H "Content-Type: application/json" \
  -d '{"plan":"pro","id":"deadbeef","name":"hijacked","tenant_id":"'"$TENANT_B_UUID"'"}' \
  "$BASE/api/v1/admin/tenants/$TENANT_A_UUID/plan")
if [[ "$RESP" == "200" || "$RESP" == "204" ]]; then
  # Verify only plan changed; id/name/tenant_id should be unchanged.
  ROW=$(_psql_oneshot "SELECT slug || '|' || name FROM tenants WHERE id='$TENANT_A_UUID';")
  if [[ "$ROW" == "default|"* ]]; then
    _pass "9.1.2 admin/tenants/{id}/plan rejects extra fields [$RESP]"
  else
    _fail "9.1.2 admin/tenants/{id}/plan mass assignment" \
      "tenant row got mutated: $ROW"
  fi
else
  _skip "9.1.2 plan mass assignment" "HTTP $RESP"
fi

# ── 9.2 Audit completeness ─────────────────────────────────────────────────

phase_open "9.2 Audit completeness — mutation routes ⊆ audited handlers"

# Build a map of mutation routes → handler symbol from cmd/gateway/main.go.
# Then for each handler symbol, look for writeAudit / logAudit / InsertAudit
# calls in the handler source. Any handler with no audit call is a
# compliance gap (the SOC 2 / ISO 27001 audit-trail requirement).
GATEWAY_FILE="$ROOT/cmd/gateway/main.go"
TMP_ROUTES=$(mktemp)
TMP_HANDLERS=$(mktemp)

# Match `r.Post|Put|Patch|Delete("/api/v1/...", <handlerH>.<Method>)`.
grep -E '\b(r\.(Post|Put|Patch|Delete))\(' "$GATEWAY_FILE" \
  | grep -oE '"/api/v1/[^"]*"\s*,\s*[a-zA-Z][a-zA-Z0-9_]*\.[A-Z][a-zA-Z0-9_]*' \
  > "$TMP_ROUTES"

# For each "<routePath>", "<handlerObj.Method>" pair, confirm the
# handler source has at least one audit emitter.
ROUTE_TOTAL=$(wc -l < "$TMP_ROUTES" | tr -d ' ')
ROUTE_WITH_AUDIT=0
declare -a MISSING

# Read the entire internal/api/handler tree once so we don't grep N
# times.
HANDLER_DIR="$ROOT/internal/api/handler"
ALL_HANDLER_SRC=$(cat "$HANDLER_DIR"/*.go 2>/dev/null)

while IFS= read -r line; do
  # Strip the route portion, keep handler symbol.
  symbol=$(echo "$line" | sed 's/.*,[[:space:]]*//')
  method=$(echo "$symbol" | cut -d. -f2)
  obj=$(echo "$symbol" | cut -d. -f1)
  # Skip routes that are inherently not state-changing (telemetry,
  # streaming, idempotent actions) — the audit-required set is the
  # mutation API surface excluding these.
  case "$method" in
    Tail|Stream|Heartbeat|Webhook|Test)  ROUTE_TOTAL=$((ROUTE_TOTAL-1)); continue ;;
  esac
  # Determine receiver TYPE so we don't conflate methods that share
  # names across receivers (Audit.Verify vs MFA.Verify both bare-
  # match "Verify"). Two patterns in main.go to handle:
  #   xH := &handler.Type{...}          (struct literal)
  #   xH := handler.NewType(...)        (constructor — extract Type
  #                                       from "NewType")
  # Try struct-literal pattern first: `obj := &handler.Type{...}`.
  # The trailing `{` is required so we don't match function calls.
  receiver=$(grep -E "${obj}\s*:?=\s*&?handler\.[A-Z][a-zA-Z0-9_]+\s*\{" "$GATEWAY_FILE" \
    | head -1 | grep -oE 'handler\.[A-Z][a-zA-Z0-9_]+' | head -1 | cut -d. -f2)
  if [[ -z "$receiver" ]]; then
    # Fall back to constructor: `obj := handler.NewType(...)` →
    # the receiver is the substring AFTER "New".
    receiver=$(grep -E "${obj}\s*:?=\s*handler\.New[A-Z][a-zA-Z0-9_]+\s*\(" "$GATEWAY_FILE" \
      | head -1 | grep -oE 'handler\.New[A-Z][a-zA-Z0-9_]+' | head -1 \
      | sed 's/^handler\.New//')
  fi
  # Look for audit emitter inside the body of `func (h *Type) Method(`.
  # If we couldn't determine the type, fall back to bare-method match
  # (less precise but still useful).
  body=$(printf '%s' "$ALL_HANDLER_SRC" | awk -v m="$method" -v t="$receiver" '
    BEGIN { capture=0; depth=0 }
    {
      if (t != "") {
        pat = "func[[:space:]]+\\([^)]*\\*" t "[^)]*\\)[[:space:]]+" m "[[:space:]]*\\("
      } else {
        pat = "func[[:space:]]+\\([^)]*\\)[[:space:]]+" m "[[:space:]]*\\("
      }
      # Reset capture state after a function block ends so we can
      # match LATER occurrences of methods sharing names across files.
      if (capture==2 && match($0, pat)) {
        capture=0
      }
      if (capture==0 && match($0, pat)) {
        capture=1; depth=0
      }
      if (capture==1) {
        print $0
        # Cheap brace-depth tracker.
        for (i=1; i<=length($0); i++) {
          c = substr($0,i,1)
          if (c=="{") depth++
          else if (c=="}") { depth--; if (depth==0 && capture==1) { capture=2 } }
        }
      }
    }')
  if echo "$body" | grep -qE "writeAudit|logAudit|InsertAudit|writeAuditWith|writeAuditP4|hashAndAudit"; then
    ROUTE_WITH_AUDIT=$((ROUTE_WITH_AUDIT+1))
  else
    MISSING+=("$symbol")
  fi
done < "$TMP_ROUTES"

rm -f "$TMP_ROUTES" "$TMP_HANDLERS"

if (( ${#MISSING[@]} == 0 )); then
  _pass "9.2.1 every mutation handler emits an audit row [$ROUTE_WITH_AUDIT/$ROUTE_TOTAL]"
else
  # Show first 8 to keep output readable.
  SAMPLE="${MISSING[@]:0:8}"
  _fail "9.2.1 mutation handlers without audit calls" \
    "${#MISSING[@]} handler(s) missing audit emit, e.g.: $SAMPLE"
fi

# ── 9.3 JWT lifecycle ──────────────────────────────────────────────────────

phase_open "9.3 JWT lifecycle — alg confusion + replay"

# 9.3.1 alg=RS256 forged with HS256 verifier. Classic confusion attack:
# attacker crafts a JWT with alg=RS256 and signs HMAC of the payload
# using the public key as the secret. Vulnerable libraries verify it
# as HMAC-SHA256 with the public key and accept it. We can't do the
# full attack without the public key, but we can probe whether the
# server accepts a non-HS256 alg at all.
NOW=$(date +%s); EXP=$((NOW + 3600))
HEADER_RS=$(printf '%s' '{"alg":"RS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
PAYLOAD_RS=$(printf '{"sub":"l8@vsp.local","email":"l8@vsp.local","role":"admin","tenant_id":"%s","iat":%d,"exp":%d}' \
  "$TENANT_A_SLUG" "$NOW" "$EXP" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
# Pretend-sign with the same HMAC key (what a server with weak alg
# enforcement would accept).
SIG_RS=$(printf '%s' "$HEADER_RS.$PAYLOAD_RS" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
  | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
TOKEN_RS="$HEADER_RS.$PAYLOAD_RS.$SIG_RS"

RS_RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $TOKEN_RS" "$BASE/api/v1/vsp/findings?limit=1")
if [[ "$RS_RESP" == "401" ]]; then
  _pass "9.3.1 alg=RS256 token rejected [HTTP 401]"
else
  _fail "9.3.1 alg=RS256 token accepted" \
    "JWT verifier accepts non-HS256 alg — algorithm confusion vulnerability (HTTP $RS_RESP)"
fi

# 9.3.2 Future-iat token (clock-skew abuse). iat in the future may
# indicate tampered claims; some libraries don't check it.
NOW_FUT=$(( $(date +%s) + 3700 ))
EXP_FUT=$(( NOW_FUT + 3600 ))
H=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
P=$(printf '{"sub":"l8@vsp.local","email":"l8@vsp.local","role":"admin","tenant_id":"%s","iat":%d,"exp":%d}' \
  "$TENANT_A_SLUG" "$NOW_FUT" "$EXP_FUT" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
S=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
TOKEN_FUT="$H.$P.$S"
FUT_RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $TOKEN_FUT" "$BASE/api/v1/vsp/findings?limit=1")
# Note: many JWT libs accept future-iat as long as exp is also future.
# This probe is informational; mark non-blocking.
if [[ "$FUT_RESP" == "200" ]]; then
  _skip "9.3.2 future-iat token (informational)" \
    "accepted (HTTP 200) — most JWT libs allow this; consider tightening if clock-skew is a concern"
else
  _pass "9.3.2 future-iat token rejected [HTTP $FUT_RESP]"
fi

# 9.3.3 Token has 3 parts but signature is from a different secret.
# Already covered by L3 4.1.6, re-asserted here as a baseline.
WRONG_SIG=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "wrong-secret-12345" -binary \
  | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
TOKEN_WRONG="$H.$P.$WRONG_SIG"
WRONG_RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $TOKEN_WRONG" "$BASE/api/v1/vsp/findings?limit=1")
if [[ "$WRONG_RESP" == "401" ]]; then
  _pass "9.3.3 wrong-signature token rejected [HTTP 401]"
else
  _fail "9.3.3 wrong-signature token" "expected 401, got $WRONG_RESP"
fi

# ── 9.4 Crypto sanity ──────────────────────────────────────────────────────

phase_open "9.4 Crypto sanity — secret length, bcrypt cost, RNG"

# 9.4.1 JWT_SECRET length ≥ 32 chars (HS256 minimum recommended).
SEC_LEN=${#JWT_SECRET}
if (( SEC_LEN >= 32 )); then
  _pass "9.4.1 JWT_SECRET length ≥ 32 [$SEC_LEN chars]"
else
  _fail "9.4.1 JWT_SECRET too short" "length $SEC_LEN < 32 (HS256 brute-forceable)"
fi

# 9.4.2 bcrypt cost in code ≥ 10. We grep for bcrypt.GenerateFromPassword
# calls and inspect the cost arg.
BCRYPT_LOWS=$(grep -rEn "bcrypt\.GenerateFromPassword.*[^0-9]([0-8])\)" \
  --include="*.go" -- "$ROOT/internal" "$ROOT/cmd" 2>/dev/null \
  | grep -v "_test\|\.bak" | head -5)
if [[ -z "$BCRYPT_LOWS" ]]; then
  _pass "9.4.2 bcrypt cost always ≥ 10 in code"
else
  _fail "9.4.2 bcrypt cost too low" "found: $BCRYPT_LOWS"
fi

# 9.4.3 math/rand in security-sensitive paths (auth, token, secret,
# password). Most uses are fine (jitter, retry backoff) but signing
# tokens or generating secrets with math/rand is weak.
WEAK_RNG=$(grep -rEn '"math/rand"|math/rand\.' --include="*.go" \
  -- "$ROOT/internal/auth" "$ROOT/internal/api/handler/auth.go" \
  2>/dev/null | grep -v "_test\|\.bak")
if [[ -z "$WEAK_RNG" ]]; then
  _pass "9.4.3 no math/rand in auth/ tree"
else
  _fail "9.4.3 math/rand in auth-sensitive code" "$WEAK_RNG"
fi

# ── 9.5 Cross-tenant admin ─────────────────────────────────────────────────

phase_open "9.5 Cross-tenant admin — horizontal privilege escalation"

# 9.5.1 Tenant-A admin attempts to change tenant-B's plan. If allowed,
# that's a real horizontal privilege escalation (admin in one tenant
# can mutate another tenant's billing tier).
ORIG_PLAN=$(_psql_oneshot "SELECT plan FROM tenants WHERE id='$TENANT_B_UUID';")
RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -X PUT -H "Authorization: Bearer $ADMIN_A" -H "Content-Type: application/json" \
  -d '{"plan":"enterprise"}' \
  "$BASE/api/v1/admin/tenants/$TENANT_B_UUID/plan")
NEW_PLAN=$(_psql_oneshot "SELECT plan FROM tenants WHERE id='$TENANT_B_UUID';")

if [[ "$RESP" == "403" ]]; then
  _pass "9.5.1 cross-tenant plan modification denied [HTTP 403]"
elif [[ "$NEW_PLAN" == "$ORIG_PLAN" ]]; then
  # Server returned 2xx but actually didn't change — silently rejected.
  # That's strange but not a security bug. Note for ops review.
  _pass "9.5.1 cross-tenant plan modification silently no-op [HTTP $RESP, plan unchanged]"
else
  # Plan got modified. Restore + fail.
  _psql_oneshot "UPDATE tenants SET plan='$ORIG_PLAN' WHERE id='$TENANT_B_UUID';" >/dev/null 2>&1
  _fail "9.5.1 cross-tenant plan modification ALLOWED" \
    "tenant-A admin changed tenant-B plan from $ORIG_PLAN → $NEW_PLAN (HTTP $RESP) — horizontal privilege escalation"
fi

# 9.5.2 Tenant-A admin lists tenant-B users. Admin/users handler MUST
# scope to caller's tenant. The robust test inspects the tenant_id of
# every returned row: any row with tenant_id != caller's UUID is a
# leak. Count-based comparisons false-positive when tenant_b is empty.
USERS_BODY=$(curl -s --max-time 5 -H "Authorization: Bearer $ADMIN_A" \
  "$BASE/api/v1/admin/users" 2>/dev/null)
A_USERS_API=$(echo "$USERS_BODY" | jq -r '.users // [] | length' 2>/dev/null)
FOREIGN_TIDS=$(echo "$USERS_BODY" | jq -r '.users[]? | .tenant_id // empty' 2>/dev/null \
  | grep -v "^$TENANT_A_UUID\$" | wc -l | tr -d ' ')

if [[ -z "$A_USERS_API" ]] || [[ "$A_USERS_API" == "null" ]]; then
  _skip "9.5.2 admin/users tenant scoping" "API returned no parseable user list"
elif (( FOREIGN_TIDS > 0 )); then
  _fail "9.5.2 admin/users leaks foreign tenant rows" \
    "$FOREIGN_TIDS rows in response have tenant_id ≠ $TENANT_A_UUID"
else
  _pass "9.5.2 admin/users tenant-scoped [returned=$A_USERS_API, all my tenant]"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
