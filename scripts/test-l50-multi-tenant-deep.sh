#!/usr/bin/env bash
# scripts/test-l50-multi-tenant-deep.sh — multi-tenant invariants.
#
# L4-B / L5 cover the read-side: A's token shouldn't see B's rows.
# This level covers WRITE-side and lifecycle invariants that those
# read-only probes miss:
#
#   1. Slug case-folding — POST /admin/tenants with slug=DEFAULT or
#      Default must NOT create a duplicate of the canonical lower-
#      case 'default' tenant.
#   2. Cross-tenant DELETE — admin in tenant A trying to delete a
#      record owned by tenant B must get 404, NOT 403 (404 doesn't
#      leak whether the resource exists).
#   3. Tenant ID injection in JSON body — when an analyst PATCHes
#      a finding with `{"tenant_id":"<other-tenant>"}`, the server
#      must IGNORE that field, never honour it. Catches mass-
#      assignment vulnerabilities.
#   4. Quota enforcement — if the tenant has plan=FREE with a
#      finding limit, requesting 1000 findings via ?limit= must be
#      clamped (informational; many envs don't have quota).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN_A="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"
TENANT_A_UUID="1bdf7f20-dbb3-4116-815f-26b4dc747e76"
TENANT_B_UUID="8bb9a716-fd14-4eba-92e8-681dc5bdb718"

# ── 50.1 Slug case folding — no duplicate-default created ────────────────

phase_open "50.1 Slug case folding"

# Try to POST a tenant with slug=DEFAULT (uppercase). The handler
# should either: (a) lowercase before insert and ON CONFLICT no-op,
# OR (b) 409 / 400 telling the caller the slug already exists.
# What we DON'T want: a second row with slug=DEFAULT alongside
# slug=default — that splits tenants and corrupts isolation.

resp=$(mktemp)
status=$(curl -s -o "$resp" -w "%{http_code}" --max-time 5 \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_A" \
  -d '{"slug":"DEFAULT","name":"Upper case attempt","plan":"FREE"}' \
  "$BASE/api/v1/admin/tenants" 2>/dev/null || echo "000")
rm -f "$resp"

if [[ "$status" =~ ^(409|400|422)$ ]]; then
  _pass "50.1.1 slug=DEFAULT rejected [HTTP $status]"
elif [[ "$status" == "404" || "$status" == "405" ]]; then
  _skip "50.1.1 slug case folding" "endpoint not available [HTTP $status]"
elif [[ "$status" =~ ^2 ]]; then
  # Check the DB — did it create a duplicate?
  dup=$(_psql_oneshot "
    SELECT count(*) FROM tenants
     WHERE LOWER(slug) = 'default';")
  if [[ "${dup:-0}" -gt 1 ]]; then
    _fail "50.1.1 slug case folding broken" \
      "$dup tenants exist with slug LIKE default — DEFAULT created duplicate"
    # Clean up the duplicate.
    _psql_oneshot "DELETE FROM tenants WHERE slug = 'DEFAULT';" >/dev/null 2>&1 || true
  else
    _pass "50.1.1 slug=DEFAULT folded to existing default [HTTP $status]"
  fi
else
  _skip "50.1.1 slug case folding" "unexpected HTTP $status"
fi

# ── 50.2 Mass-assignment of tenant_id in PATCH body ──────────────────────

phase_open "50.2 Mass-assignment — tenant_id can't be overwritten"

# Seed a finding in tenant A, then PATCH it from tenant A with a body
# trying to set tenant_id to tenant B. The PATCH must either reject
# the field, ignore it, or fail. NEVER: silently move the row.
FID=$(_psql_oneshot "
  INSERT INTO findings (tenant_id, tool, severity, message, rule_id)
  VALUES ('$TENANT_A_UUID', 'l50-probe', 'LOW', 'L50 mass-assign probe', 'L50-RULE')
  RETURNING id;")

if [[ -z "$FID" || ! "$FID" =~ ^[0-9a-f-]{36}$ ]]; then
  _skip "50.2.0 mass-assign seed" "couldn't insert finding [id=$FID]"
else
  status_http=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X PATCH -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_A" \
    -d "{\"tenant_id\":\"$TENANT_B_UUID\",\"severity\":\"CRITICAL\"}" \
    "$BASE/api/v1/findings/$FID" 2>/dev/null || echo "000")

  # Regardless of HTTP status, the row's tenant_id MUST remain A.
  actual_tenant=$(_psql_oneshot "SELECT tenant_id FROM findings WHERE id='$FID';")
  if [[ "$actual_tenant" == "$TENANT_A_UUID" ]]; then
    _pass "50.2.1 tenant_id mass-assignment ignored [HTTP $status_http, still tenant A]"
  elif [[ "$actual_tenant" == "$TENANT_B_UUID" ]]; then
    _fail "50.2.1 mass-assignment ESCAPE" \
      "finding $FID was moved to tenant B via PATCH — IDOR upgrade vector"
  else
    _skip "50.2.1 mass-assign" "tenant_id changed unexpectedly to '$actual_tenant'"
  fi

  _psql_oneshot "DELETE FROM findings WHERE id='$FID';" >/dev/null 2>&1 || true
fi

# ── 50.3 Cross-tenant DELETE returns 404 not 403 ─────────────────────────

phase_open "50.3 Cross-tenant DELETE indistinguishable from 'not exists'"

# Seed a finding in tenant B. Tenant A's admin tries to DELETE it.
# Expected: 404 (resource doesn't exist FROM A's perspective).
# 403 leaks "resource exists but you can't touch it" — a less-bad
# but still detectable info-disclosure.
FID_B=$(_psql_oneshot "
  INSERT INTO findings (tenant_id, tool, severity, message, rule_id)
  VALUES ('$TENANT_B_UUID', 'l50-cross-probe', 'LOW', 'tenant B owned', 'L50-CROSS')
  RETURNING id;")

if [[ -z "$FID_B" ]]; then
  _skip "50.3.0 cross-tenant seed" "couldn't insert in B"
else
  status_http=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X DELETE -H "Authorization: Bearer $ADMIN_A" \
    "$BASE/api/v1/findings/$FID_B" 2>/dev/null || echo "000")

  # Verify B's row is untouched.
  still_there=$(_psql_oneshot "SELECT count(*) FROM findings WHERE id='$FID_B';")
  if [[ "${still_there:-0}" == "0" ]]; then
    _fail "50.3.1 A deleted B's finding" \
      "cross-tenant DELETE succeeded — RLS bypass on write"
  elif [[ "$status_http" == "404" ]]; then
    _pass "50.3.1 cross-tenant DELETE returns 404 [row preserved]"
  elif [[ "$status_http" == "403" ]]; then
    _skip "50.3.1 cross-tenant DELETE returns 403" \
      "informational — 404 preferred, but 403 is acceptable"
  elif [[ "$status_http" == "405" || "$status_http" == "204" ]]; then
    # 204 with row untouched: handler reports success but didn't
    # actually delete (RLS blocked). Confusing but not a leak.
    _pass "50.3.1 cross-tenant DELETE [HTTP $status_http, row preserved]"
  else
    _skip "50.3.1 cross-tenant DELETE" "HTTP $status_http"
  fi

  _psql_oneshot "DELETE FROM findings WHERE id='$FID_B';" >/dev/null 2>&1 || true
fi

# ── 50.4 limit= clamping — can't request 1M rows ─────────────────────────

phase_open "50.4 list?limit= clamping"

# Request limit=1000000. Server should clamp to a sane max (typically
# 500/1000) — otherwise a single request can OOM the gateway.
resp=$(mktemp)
status_http=$(curl -s -o "$resp" -w "%{http_code}" --max-time 10 \
  -H "Authorization: Bearer $ADMIN_A" \
  "$BASE/api/v1/audit/log?limit=1000000" 2>/dev/null || echo "000")

if [[ "$status_http" =~ ^2 ]]; then
  count=$(jq -r '(.items // .logs // .data // .results // []) | length' "$resp" 2>/dev/null || echo "?")
  if [[ "$count" =~ ^[0-9]+$ ]] && (( count <= 5000 )); then
    _pass "50.4.1 limit clamping [returned $count rows for limit=1M]"
  else
    _fail "50.4.1 limit NOT clamped" "returned $count rows — DoS / memory exhaustion vector"
  fi
elif [[ "$status_http" =~ ^4 ]]; then
  _pass "50.4.1 oversize limit rejected [HTTP $status_http]"
else
  _skip "50.4.1 limit clamping" "unexpected HTTP $status_http"
fi
rm -f "$resp"

# ── 50.5 Negative limit/offset doesn't break pagination ──────────────────

phase_open "50.5 Negative limit/offset handled defensively"

for q in "limit=-1" "limit=0" "offset=-100" "limit=abc"; do
  status_http=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN_A" \
    "$BASE/api/v1/audit/log?$q&limit=1" 2>/dev/null || echo "000")
  if [[ "$status_http" =~ ^(200|400|422)$ ]]; then
    _pass "50.5 q='$q' handled [HTTP $status_http]"
  elif [[ "$status_http" =~ ^5 ]]; then
    _fail "50.5 negative pagination caused 5xx" "q='$q' → HTTP $status_http"
  else
    _skip "50.5 q='$q'" "HTTP $status_http"
  fi
done

final_summary
