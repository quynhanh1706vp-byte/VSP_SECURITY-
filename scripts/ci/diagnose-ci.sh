#!/usr/bin/env bash
# diagnose-sd-0049.sh
# First-pass diagnostic for CI gate failures. Runs locally what CI runs.
# Prints where the gap is. Does not modify anything.
# Does not modify anything.

set -euo pipefail

QUICK=0
[[ "${1:-}" == "--quick" ]] && QUICK=1

section() { printf "\n\033[1;36m━━ %s ━━\033[0m\n" "$1"; }
ok()      { printf "\033[1;32m✓\033[0m %s\n"  "$1"; }
warn()    { printf "\033[1;33m⚠\033[0m %s\n"  "$1"; }
bad()     { printf "\033[1;31m✗\033[0m %s\n"  "$1"; }
info()    { printf "  %s\n" "$1"; }

FAIL=0
WARNS=0

# ── 1. Toolchain ────────────────────────────────────────────────────────────
section "1. Toolchain"

for tool in go golangci-lint gitleaks trivy semgrep gh jq; do
  if command -v "$tool" >/dev/null 2>&1; then
    v=$("$tool" --version 2>&1 | head -1 || echo "unknown")
    ok "$tool present — $v"
  else
    warn "$tool not installed locally (CI may still have it)"
    WARNS=$((WARNS+1))
  fi
done

# ── 2. Billing module check (the actual SD-0049) ────────────────────────────
section "2. Billing module — SD-0049 target"

if [[ -d "./internal/billing" ]] || [[ -d "./cmd/billing" ]]; then
  ok "Billing module found"

  section "2a. Billing — build"
  if go build ./internal/billing/... ./cmd/billing/... 2>&1; then
    ok "Billing builds clean"
  else
    bad "Billing build FAILED — this is almost certainly the SD-0049 root cause"
    FAIL=$((FAIL+1))
  fi

  section "2b. Billing — tests"
  if go test ./internal/billing/... ./cmd/billing/... -count=1 2>&1 | tee /tmp/billing-test.log; then
    ok "Billing tests pass"
  else
    bad "Billing tests FAILED — check /tmp/billing-test.log"
    FAIL=$((FAIL+1))
  fi

  section "2c. Billing — coverage"
  go test -coverprofile=/tmp/billing-cov.out ./internal/billing/... 2>&1 >/dev/null || true
  if [[ -f /tmp/billing-cov.out ]]; then
    cov=$(go tool cover -func=/tmp/billing-cov.out | tail -1 | awk '{print $3}')
    info "Billing coverage: $cov"
    pct=$(echo "$cov" | tr -d '%' | cut -d. -f1)
    if [[ "$pct" -lt 70 ]]; then
      warn "Coverage < 70% — may be what CI gate is blocking on"
      WARNS=$((WARNS+1))
    else
      ok "Coverage >= 70%"
    fi
  fi
else
  warn "No billing module found at ./internal/billing or ./cmd/billing"
  warn "Check if the gate name 'billing-sd-0049' matches an actual job"
  WARNS=$((WARNS+1))
fi

# ── 3. Lint — what does golangci-lint say overall? ──────────────────────────
section "3. golangci-lint snapshot"

if command -v golangci-lint >/dev/null 2>&1; then
  total=$(golangci-lint run --out-format=line-number 2>/dev/null | wc -l || echo 0)
  info "Total issues: $total"

  nilerr=$(golangci-lint run --enable=nilerr --disable-all --out-format=line-number 2>/dev/null | wc -l || echo 0)
  if [[ "$nilerr" -gt 0 ]]; then
    bad "$nilerr nilerr issues — logic bugs, must fix (Sprint 4 S4-4)"
    FAIL=$((FAIL+1))
  else
    ok "0 nilerr issues"
  fi

  errcheck=$(golangci-lint run --enable=errcheck --disable-all --out-format=line-number 2>/dev/null | wc -l || echo 0)
  info "errcheck: $errcheck"
fi

# ── 4. Secrets check ────────────────────────────────────────────────────────
section "4. Secrets scan"

if command -v gitleaks >/dev/null 2>&1; then
  if gitleaks detect --source . --no-banner --redact -v 2>&1 | tail -5; then
    ok "gitleaks found no secrets"
  else
    bad "gitleaks found leaked secrets — fix before push"
    FAIL=$((FAIL+1))
  fi
fi

# ── 5. Last 10 CI runs on main ──────────────────────────────────────────────
section "5. Last 10 CI runs on main"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  gh run list --branch main --limit 10 --json status,conclusion,name,displayTitle,createdAt \
    | jq -r '.[] | "\(.createdAt[:10])  \(.conclusion // "running" | ascii_upcase)  \(.name)  \(.displayTitle)"' \
    | while read -r line; do
        if [[ "$line" == *SUCCESS* ]]; then
          ok "$line"
        elif [[ "$line" == *FAILURE* ]]; then
          bad "$line"
        else
          info "$line"
        fi
      done
else
  warn "gh not available or not authenticated — cannot pull CI history"
  WARNS=$((WARNS+1))
fi

# ── 6. Summary ──────────────────────────────────────────────────────────────
section "Summary"

echo "  Failures: $FAIL"
echo "  Warnings: $WARNS"
echo ""

if [[ $FAIL -gt 0 ]]; then
  bad "Gate is red because of the failures above. Fix top-to-bottom."
  echo ""
  echo "Suggested next steps:"
  echo "  1. If billing module build/test failed, check go.mod version drift."
  echo "  2. If nilerr > 0, grep for 'err != nil' patterns returning early."
  echo "  3. If secrets found, rotate credentials FIRST, then clean git history."
  echo "  4. Re-run this script until Failures: 0."
  exit 1
fi

if [[ $WARNS -gt 0 ]]; then
  warn "No hard failures but $WARNS warnings. Gate may pass with WARN."
  exit 0
fi

ok "Everything green locally. If CI is still red, cache or infra issue — check runner logs."
