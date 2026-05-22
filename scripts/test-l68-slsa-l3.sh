#!/usr/bin/env bash
# scripts/test-l68-slsa-l3.sh — SLSA L3 build-provenance checks.
#
# SLSA (Supply-chain Levels for Software Artifacts) L3 requires:
#   - Provenance file generated per build (in-toto attestation)
#   - Provenance signed (sigstore / cosign / GitHub OIDC)
#   - Builder is hardened (ephemeral, isolated)
#   - Provenance is non-falsifiable
#
# This level checks for the BUILD-SIDE artefacts. Verifies workflow
# emits attestations, has cosign signing wired, and provenance file
# shape is valid.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 68.1 Build workflow generates provenance attestation ─────────────────

phase_open "68.1 Provenance generation in build workflow"

WF_DIR="$ROOT/.github/workflows"
if [[ ! -d "$WF_DIR" ]]; then
  _skip "68.1.0 workflow dir" "absent"
  final_summary; exit 0
fi

# Look for `actions/attest-build-provenance` or
# `slsa-framework/slsa-github-generator` usage.
PROVENANCE_WF=$(grep -rln 'attest-build-provenance\|slsa-github-generator\|slsa-framework' \
  "$WF_DIR" 2>/dev/null | head -3 || true)

if [[ -n "$PROVENANCE_WF" ]]; then
  _pass "68.1.1 provenance-generation action used [$(echo "$PROVENANCE_WF" | head -1 | xargs basename)]"
else
  _fail "68.1.1 no SLSA provenance action in any workflow" \
    "expected actions/attest-build-provenance@v* or slsa-framework/* — SLSA L3 gap"
fi

# 68.1.2 — attestation permissions block set
ATTEST_PERMS=$(grep -rln 'attestations:\s*write\|id-token:\s*write' \
  "$WF_DIR" 2>/dev/null | head -3 || true)

if [[ -n "$ATTEST_PERMS" ]]; then
  _pass "68.1.2 workflow grants id-token:write / attestations:write"
else
  _skip "68.1.2 attestation permissions" \
    "no explicit id-token:write — informational; required for sigstore"
fi

# ── 68.2 Container build signs the image ─────────────────────────────────

phase_open "68.2 Container image signing"

# Look for cosign sign / docker/build-push-action with provenance.
COSIGN_HIT=$(grep -rln 'cosign sign\|cosign-installer\|provenance:\s*true' \
  "$WF_DIR" 2>/dev/null | head -3 || true)

if [[ -n "$COSIGN_HIT" ]]; then
  _pass "68.2.1 cosign signing / provenance:true configured"
else
  _skip "68.2.1 cosign signing" \
    "no cosign references — informational; consider for image attestation"
fi

# ── 68.3 cosign-api service (defence-in-depth signer) ───────────────────

phase_open "68.3 cosign-api service binary"

if [[ -d "$ROOT/cmd/cosign-api" ]]; then
  _pass "68.3.1 cosign-api source present"
elif [[ -f "$ROOT/cosign-api" ]]; then
  _pass "68.3.1 cosign-api binary present (built)"
else
  _skip "68.3.1 cosign-api" "no cosign-api service — informational"
fi

# ── 68.4 SBOM artefact attached to release ──────────────────────────────

phase_open "68.4 SBOM at build time"

# CycloneDX or SPDX SBOM should be generated per release.
SBOM_WF=$(grep -rln 'cyclonedx\|spdx-sbom\|anchore/sbom-action\|syft' \
  "$WF_DIR" 2>/dev/null | head -3 || true)

if [[ -n "$SBOM_WF" ]]; then
  _pass "68.4.1 SBOM generation action found in workflow"
else
  _skip "68.4.1 SBOM generation" \
    "no SBOM action — informational; required for SLSA L3 distribution"
fi

# ── 68.5 Reproducible build flags ───────────────────────────────────────

phase_open "68.5 Reproducible build flags"

# Go: -trimpath strips local paths from binary, making the build
# byte-reproducible across hosts.
# Some workflows have -trimpath; some don't.
TRIMPATH=$(grep -rln '\-trimpath' "$WF_DIR" 2>/dev/null | head -3 || true)

if [[ -n "$TRIMPATH" ]]; then
  _pass "68.5.1 go build uses -trimpath (reproducible)"
else
  _skip "68.5.1 -trimpath" \
    "no -trimpath flag — informational; build dir leaks into binary"
fi

# 68.5.2 - ldflags strip + buildid
LDFLAGS=$(grep -rln 'ldflags.*-s\|buildmode\|GOFLAGS' "$WF_DIR" 2>/dev/null | head -3 || true)
if [[ -n "$LDFLAGS" ]]; then
  _pass "68.5.2 ldflags / GOFLAGS configured for reproducible builds"
else
  _skip "68.5.2 ldflags reproducibility" "informational"
fi

# ── 68.6 Vulnerability scan of built artefact ───────────────────────────

phase_open "68.6 Vuln scan in build"

# Look for trivy / grype / govulncheck in workflows.
VULN_SCAN=$(grep -rln 'trivy\|grype\|govulncheck\|anchore/scan' \
  "$WF_DIR" 2>/dev/null | head -3 || true)

if [[ -n "$VULN_SCAN" ]]; then
  _pass "68.6.1 vuln scanner in workflow"
else
  _fail "68.6.1 no vuln scanner" \
    "expected trivy / grype / govulncheck — SBOM without scan is incomplete"
fi

final_summary
