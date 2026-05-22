#!/usr/bin/env bash
# test-l1-smoke.sh — VSP Level 1 smoke test (~15 min target, ~5 sec actual).
#
# Runs 9 lightweight checks per docs/TEST_ROADMAP.md §2. Catches ~80%
# of regressions in 5 seconds — designed for daily use + CI.
#
# Usage:
#   export TOKEN_ADMIN=$(./scripts/mint_jwt_local.sh admin@vsp.local admin)
#   ./scripts/test-l1-smoke.sh
#
# Optional env:
#   BASE        — gateway URL (default http://127.0.0.1:8921)
#   FILTER      — only run tests whose name contains this string
#
# Exit code: 0 = all pass, 1 = any fail, 2 = config error.

set -uo pipefail
cd "$(dirname "$0")/.."

. "$(dirname "$0")/lib/vsp-test.sh"

require_command curl jq
require_env TOKEN_ADMIN

AUTH="-H Authorization:\ Bearer\ $TOKEN_ADMIN"
# shellcheck disable=SC2086 — we want word-splitting on AUTH
auth_header() { printf -- "-H\nAuthorization: Bearer %s\n" "$TOKEN_ADMIN"; }

printf "%s%s VSP L1 Smoke Test%s\n" "$C_BOLD" "$C_GREEN" "$C_RESET"
printf "Base: %s\n" "$BASE"
printf "Token: %s…\n" "${TOKEN_ADMIN:0:24}"

phase_open "L1 — Smoke checks"

# 1.1 Gateway alive (auth check is a cheap admin endpoint).
assert_status "1.1 Gateway alive (auth/check)" \
  "/api/v1/auth/check" 200 \
  -H "Authorization: Bearer $TOKEN_ADMIN"

# 1.2 Auth required for protected endpoints.
assert_status "1.2 Unauthenticated request blocked" \
  "/api/v1/vsp/findings" 401

# 1.3 Public status endpoint returns operational shape.
assert_json "1.3 Public status JSON shape" \
  "/api/v1/status" '.components | length' 3

# 1.4 KPI sanity green — release blocker if 409.
assert_status "1.4 KPI sanity (CI release gate)" \
  "/api/v1/kpi/sanity" 200 \
  -H "Authorization: Bearer $TOKEN_ADMIN"

# 1.5 Audit chain integrity — must be ok=true.
assert_json "1.5 Audit chain verify" \
  "/api/v1/audit/verify" '.ok' "true" \
  -X POST -H "Authorization: Bearer $TOKEN_ADMIN"

# 1.6 DORA endpoint returns 4 metric blocks with tier strings.
assert_json "1.6 DORA deploy_frequency tier present" \
  "/api/v1/dora?days=30" '.deploy_frequency.tier | type' "string" \
  -H "Authorization: Bearer $TOKEN_ADMIN"

# 1.7 Trust Center page (anonymous, HTML). Sprint 12.6 fix: the
# previous /trust → /trust/ redirect collided with chimw.StripSlashes
# producing an infinite loop. /trust now serves index.html directly.
assert_status "1.7 Trust Center page" "/trust" 200

# 1.8 RFC 9116 security.txt has Contact: directive.
contact_count=$(curl -s --max-time 5 "$BASE/.well-known/security.txt" \
                | grep -c '^Contact:' 2>/dev/null || echo 0)
assert_eq "1.8 security.txt Contact: line" "$contact_count" "2"

# 1.9 Self-SBOM endpoint (CycloneDX).
assert_json "1.9 Self-SBOM CycloneDX format" \
  "/sbom.cyclonedx.json" '.bomFormat' "CycloneDX"

phase_close

final_summary
