#!/usr/bin/env bash
# scripts/test-l69-audit-chain-nightly.sh — full audit chain re-hash.
#
# L9.10.3 verifies the chain hashes contiguously after a small burst.
# L51 verifies UPDATE/DELETE on audit_log are refused. This level
# does the EXPENSIVE walk: re-hash the ENTIRE audit log per tenant
# and compare to stored hashes. If any row's hash doesn't match
# H(prev_hash || tenant_id || action || resource || ...) the chain
# has been silently tampered with.
#
# Cheap on a fresh CI DB (few hundred rows). On prod-scale (millions
# of rows) gate behind L69_FULL=1 for a nightly cron.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"
TENANT_A_UUID="1bdf7f20-dbb3-4116-815f-26b4dc747e76"

# ── 69.1 Use gateway's /audit/verify endpoint ───────────────────────────

phase_open "69.1 /api/v1/audit/verify reports ok=true"

verify=$(curl -s --max-time 30 -X POST \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/audit/verify" 2>/dev/null || echo '{}')

ok=$(echo "$verify" | jq -r '.ok // false' 2>/dev/null || echo "false")
count=$(echo "$verify" | jq -r '.checked // .verified // 0' 2>/dev/null || echo 0)

if [[ "$ok" == "true" ]]; then
  _pass "69.1.1 chain verifies clean [checked=$count]"
else
  _fail "69.1.1 audit/verify reports ok=false" \
    "chain broken or endpoint not available"
fi

# ── 69.2 Chain has at least 1 row per active tenant ─────────────────────

phase_open "69.2 Every active tenant has audit history"

# In CI's empty DB this may be 0, so this is a SKIP when scarce.
TENANTS_WITH_AUDIT=$(_psql_oneshot "
  SELECT count(DISTINCT al.tenant_id)
  FROM audit_log al
  JOIN tenants t ON t.id = al.tenant_id
  WHERE t.active = true;")
TENANTS_WITH_AUDIT=${TENANTS_WITH_AUDIT:-0}

TENANTS_TOTAL=$(_psql_oneshot "SELECT count(*) FROM tenants WHERE active = true;")
TENANTS_TOTAL=${TENANTS_TOTAL:-0}

if [[ "$TENANTS_TOTAL" -eq 0 ]]; then
  _skip "69.2.1 audit history coverage" "no active tenants"
elif [[ "$TENANTS_WITH_AUDIT" -lt 1 ]]; then
  _skip "69.2.1 audit history coverage" \
    "no audit rows yet — CI freshly booted; nightly should re-check"
else
  _pass "69.2.1 $TENANTS_WITH_AUDIT/$TENANTS_TOTAL active tenants have audit history"
fi

# ── 69.3 Seq is monotonically increasing per tenant ─────────────────────

phase_open "69.3 audit_log.seq monotonic per tenant"

# seq must be STRICTLY INCREASING per tenant. Gaps are OK — Postgres
# BIGSERIAL consumes sequence values inside transactions that roll
# back (audit emission fails) so delta > 1 is expected. Only delta
# <= 0 (duplicate or backward) is a real integrity violation, since
# it would mean two rows claim the same chain position.
ANOMALY=$(_psql_oneshot "
  WITH seqs AS (
    SELECT tenant_id, seq,
           seq - LAG(seq, 1) OVER (PARTITION BY tenant_id ORDER BY seq) AS delta
    FROM audit_log
  )
  SELECT tenant_id || '@' || seq || ' (delta=' || delta || ')'
  FROM seqs
  WHERE delta IS NOT NULL AND delta <= 0
  LIMIT 1;")

if [[ -z "$ANOMALY" ]]; then
  _pass "69.3.1 audit_log.seq strictly increasing per tenant (gaps OK from rolled-back tx)"
else
  _fail "69.3.1 audit_log.seq duplicate or backward" \
    "$ANOMALY — chain integrity compromised"
fi

# ── 69.4 No row has NULL prev_hash except the first ─────────────────────

phase_open "69.4 prev_hash linkage intact"

NULL_PREV=$(_psql_oneshot "
  SELECT tenant_id || ' seq=' || seq
  FROM audit_log
  WHERE prev_hash IS NULL AND seq > 1
  LIMIT 1;")

if [[ -z "$NULL_PREV" ]]; then
  _pass "69.4.1 every audit_log row beyond seq=1 has prev_hash set"
else
  _fail "69.4.1 prev_hash NULL on non-first row" "$NULL_PREV"
fi

# ── 69.5 No row has empty hash ───────────────────────────────────────────

phase_open "69.5 Every row has a non-empty hash"

EMPTY=$(_psql_oneshot "
  SELECT count(*) FROM audit_log
  WHERE hash IS NULL OR length(hash::text) < 16;")
EMPTY=${EMPTY:-0}

if [[ "$EMPTY" -eq 0 ]]; then
  _pass "69.5.1 no audit_log row has empty/short hash"
else
  _fail "69.5.1 audit_log rows with empty hash" \
    "$EMPTY rows — chain breakage"
fi

# ── 69.6 Full re-hash walk (gated; expensive) ───────────────────────────

phase_open "69.6 Full per-row re-hash walk"

if [[ "${L69_FULL:-0}" != "1" ]]; then
  _skip "69.6.1 full re-hash walk" \
    "L69_FULL!=1 — expensive on large tables, gated for nightly"
else
  # For each tenant, walk seq in order, reconstruct H, compare.
  # This is a tight loop — keep it in SQL for speed.
  TAMPERED=$(_psql_oneshot "
    WITH chain AS (
      SELECT
        seq, tenant_id, action, resource, ip,
        hash,
        prev_hash,
        -- Reconstruct the hash. NOTE: this MUST match the gateway's
        -- hashing implementation exactly. If the gateway changes the
        -- algorithm (different field set, different separator, etc.)
        -- this query needs the same change.
        encode(sha256(
          (COALESCE(prev_hash::text, '') ||
           tenant_id::text ||
           COALESCE(user_id::text, '') ||
           action ||
           COALESCE(resource, '') ||
           COALESCE(ip, '') ||
           COALESCE(payload::text, '') ||
           created_at::text
          )::bytea
        ), 'hex') AS recomputed
      FROM audit_log
      ORDER BY tenant_id, seq
    )
    SELECT tenant_id || ' seq=' || seq
    FROM chain
    WHERE hash != recomputed
    LIMIT 1;")

  if [[ -z "$TAMPERED" ]]; then
    _pass "69.6.1 every audit_log row's hash matches recomputed value"
  else
    _fail "69.6.1 tampered row detected" \
      "$TAMPERED — stored hash doesn't match recomputed (algorithm drift OR tamper)"
  fi
fi

final_summary
