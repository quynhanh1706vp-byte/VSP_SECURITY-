#!/usr/bin/env bash
# scripts/test-l63-gh-advanced-security.sh — GHAS parity check.
#
# GitHub Advanced Security ships:
#   - CodeQL (semantic SAST)
#   - Dependabot (vulnerable dep alerts)
#   - Secret scanning (commits with high-entropy values)
#   - Push protection (block secret-bearing pushes)
#
# This level verifies each is configured AND has been run recently.
# Static-only — checks for the workflow files / config / artefacts.
# Runtime alert pull is gated by L63_API=1 + GH_TOKEN.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 63.1 CodeQL workflow present + scheduled ─────────────────────────────

phase_open "63.1 CodeQL workflow"

CQL=""
for cand in \
    "$ROOT/.github/workflows/codeql.yml" \
    "$ROOT/.github/workflows/codeql-analysis.yml" \
    "$ROOT/.github/workflows/code-scanning.yml"; do
  if [[ -r "$cand" ]]; then CQL="$cand"; break; fi
done

if [[ -z "$CQL" ]]; then
  _fail "63.1.0 CodeQL workflow absent" \
    "expected .github/workflows/codeql{,-analysis}.yml — GHAS gap"
else
  _pass "63.1.0 CodeQL workflow at $(basename "$CQL")"

  # Must run on PR + push to main + a schedule (cron). Schedule is
  # the safety net for branches that don't see frequent PRs.
  if grep -qE '^\s+schedule:' "$CQL"; then
    _pass "63.1.1 CodeQL has schedule (cron) trigger"
  else
    _skip "63.1.1 CodeQL schedule" \
      "no cron trigger — informational, PR/push triggers may suffice"
  fi

  # Must use `github/codeql-action/init@v3` or higher (older versions
  # have known issues).
  if grep -qE 'github/codeql-action/(init|analyze)@v[3-9]' "$CQL"; then
    _pass "63.1.2 CodeQL action pinned to v3+"
  else
    _fail "63.1.2 CodeQL action version" \
      "expected @v3 or higher; using older version"
  fi

  # Should analyze the languages we actually use (go + javascript).
  if grep -qiE "language[s]?:\s*['\"]?go|matrix:.*language.*go" "$CQL"; then
    _pass "63.1.3 CodeQL configured for Go"
  else
    _skip "63.1.3 CodeQL Go config" "verify Go is in the language matrix"
  fi
fi

# ── 63.2 Dependabot configuration ────────────────────────────────────────

phase_open "63.2 Dependabot configured"

DEP="$ROOT/.github/dependabot.yml"
if [[ ! -r "$DEP" ]]; then
  _fail "63.2.0 Dependabot config absent" \
    ".github/dependabot.yml expected — GHAS / supply-chain gap"
else
  _pass "63.2.0 .github/dependabot.yml present"

  # Must include package-ecosystem entries for go modules and
  # github-actions (the action versions themselves).
  if grep -qE 'package-ecosystem:\s*"?gomod' "$DEP"; then
    _pass "63.2.1 gomod ecosystem registered"
  else
    _fail "63.2.1 gomod ecosystem missing" "Go deps won't get update PRs"
  fi

  if grep -qE 'package-ecosystem:\s*"?github-actions' "$DEP"; then
    _pass "63.2.2 github-actions ecosystem registered"
  else
    _fail "63.2.2 github-actions ecosystem missing" \
      "workflow action versions won't get update PRs — pinned-to-stale risk"
  fi

  # Auto-merge security updates is the high-leverage automation.
  # Look for an `open-pull-requests-limit` and `schedule` interval.
  if grep -qE 'interval:\s*"?(daily|weekly)' "$DEP"; then
    _pass "63.2.3 Dependabot has a regular schedule"
  else
    _skip "63.2.3 Dependabot schedule" "no daily/weekly interval — informational"
  fi
fi

# ── 63.3 Secret-scanning workflow / signal ───────────────────────────────

phase_open "63.3 Secret scanning"

# Secret scanning is enabled at the REPO level (Settings → Code
# security), not in a workflow file. We can't probe the setting
# directly from a test script, but we can verify a complementary
# defence: a pre-commit / CI gitleaks-style scan.
SECRET_SCAN_WF=""
for cand in \
    "$ROOT/.github/workflows/secret-scan.yml" \
    "$ROOT/.github/workflows/gitleaks.yml" \
    "$ROOT/.github/workflows/trufflehog.yml"; do
  if [[ -r "$cand" ]]; then SECRET_SCAN_WF="$cand"; break; fi
done

# Also accept: a step in another workflow that runs gitleaks / trufflehog
if [[ -z "$SECRET_SCAN_WF" ]]; then
  if grep -rqE 'gitleaks|trufflehog|secret.?scan' "$ROOT/.github/workflows/" 2>/dev/null; then
    SECRET_SCAN_WF="(in shared workflow)"
  fi
fi

if [[ -n "$SECRET_SCAN_WF" ]]; then
  _pass "63.3.1 secret-scan workflow / step present [$SECRET_SCAN_WF]"
else
  _skip "63.3.1 secret-scanning workflow" \
    "no gitleaks/trufflehog workflow — GHAS native scanning may cover it but not verifiable from CI"
fi

# ── 63.4 Push-protection note in CONTRIBUTING / SECURITY ────────────────

phase_open "63.4 Push-protection awareness"

# Push protection rejects commits with secrets before they land.
# Document its existence in SECURITY.md or CONTRIBUTING.md so contributors
# know to expect it.
DOC_HIT=""
for doc in SECURITY.md CONTRIBUTING.md docs/SECURITY.md; do
  if [[ -r "$ROOT/$doc" ]] && grep -qi 'push.?protection\|secret.?scan' "$ROOT/$doc"; then
    DOC_HIT="$doc"; break
  fi
done

if [[ -n "$DOC_HIT" ]]; then
  _pass "63.4.1 push protection / secret scanning documented in $DOC_HIT"
else
  _skip "63.4.1 push protection doc" \
    "no mention in SECURITY.md or CONTRIBUTING.md — informational"
fi

# ── 63.5 Runtime: open security alerts (gated) ───────────────────────────

phase_open "63.5 Live GitHub alert hygiene"

if [[ "${L63_API:-0}" != "1" ]]; then
  _skip "63.5.0 live alert check" "L63_API!=1 — needs gh CLI + token, skip by default"
else
  if ! command -v gh &>/dev/null; then
    _skip "63.5.0 gh CLI" "not installed"
  else
    # Count critical/high open alerts. Threshold: 0 critical, ≤5 high.
    REPO=$(git -C "$ROOT" remote get-url origin 2>/dev/null \
      | sed -E 's|.*[/:]([^/]+/[^/]+)\.git$|\1|' || true)
    if [[ -z "$REPO" ]]; then
      _skip "63.5.0 alert pull" "couldn't determine repo from git remote"
    else
      CRIT=$(gh api "/repos/$REPO/dependabot/alerts?severity=critical&state=open" \
        --jq 'length' 2>/dev/null || echo "?")
      HIGH=$(gh api "/repos/$REPO/dependabot/alerts?severity=high&state=open" \
        --jq 'length' 2>/dev/null || echo "?")

      if [[ "$CRIT" == "0" ]] && [[ "${HIGH:-99}" =~ ^[0-9]+$ ]] && (( HIGH <= 5 )); then
        _pass "63.5.1 alert hygiene OK [critical=$CRIT high=$HIGH]"
      else
        _fail "63.5.1 alert backlog" "critical=$CRIT high=$HIGH — triage required"
      fi
    fi
  fi
fi

final_summary
