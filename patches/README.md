# VSP Sprint 3.5 — Hygiene Patch Bundle

**Generated:** 2026-04-20
**Target:** VSP repo at `~/Data/GOLANG_VSP`
**Purpose:** Truth-sync + CI integrity + linter expansion to move DSOMM 2.95 → 3.2

---

## What's in this bundle

| File | Target | Drop-in? | Purpose |
|------|--------|----------|---------|
| `gitleaks.toml` | `.gitleaks.toml` | ✅ Yes | Remove 2 rotated-key allowlists, add Anthropic+Stripe rules |
| `golangci.yml` | `.golangci.yml` | ✅ Yes | Expand 6 → 18 linters with gosec+security suite |
| `SECURITY.md` | `SECURITY.md` | ✅ Yes | Truth-based rewrite matching actual code |
| `CI_FIXES.md` | `.github/workflows/ci.yml` | ⚠ Manual | 4 bug fixes in CI pipeline (need section-by-section edit) |
| `THREAT_MODEL_PATCH.md` | `THREAT_MODEL.md` | ⚠ Manual | 5 row updates to align claims with code |
| `apply_sprint35_patches.sh` | — | 🛠 Helper | Applies 3 drop-in files with git branch + backup |

---

## Quick apply (3 drop-in files only)

```bash
# 1. Download bundle to repo root
cd ~/Data/GOLANG_VSP
mkdir -p patches
# (copy all files from this bundle into ./patches/)

# 2. Run applier
bash patches/apply_sprint35_patches.sh patches/

# 3. Review diffs
git diff --stat
git diff .gitleaks.toml
git diff .golangci.yml
git diff SECURITY.md

# 4. Manually apply CI_FIXES.md + THREAT_MODEL_PATCH.md edits
#    (these need visual review — DO NOT auto-apply)

# 5. Test locally before push
golangci-lint run ./...          # new linters pass?
gitleaks detect --no-git         # no false positives?
go test ./... -race              # nothing breaks?

# 6. Commit + push
git add -A
git commit -m "fix: Sprint 3.5 hygiene — truth-sync + linter expansion"
git push -u origin fix/sprint35-hygiene-<timestamp>

# 7. Open PR for review
gh pr create --title "Sprint 3.5: hygiene + truth-sync" \
  --body "$(cat <<'EOF'
## Summary

Sprint 3.5 hygiene pass after DSOMM audit 2026-04-20.

### Truth-sync (legal + audit critical)
- **SECURITY.md** rewritten against actual code. Previous version claimed
  MFA enforced and cookie-based auth complete — neither fully true.
- **THREAT_MODEL.md** query count synced: 82/92 tenant_id (not 59/59)

### Static analysis expansion
- **.golangci.yml** 6 → 18 linters with gosec + bodyclose + sqlclosecheck
- **.gitleaks.toml** custom rules for Anthropic, Stripe, Slack formats
  (default gitleaks misses all three)

### CI integrity
- Fix 4 security-theater bugs where checks passed regardless of status
- See CI_FIXES.md in PR description for detailed bug analysis

### DSOMM impact
- Test & Verification / Static Analysis: 2.5 → 3.0
- Culture & Org / Design: 3.0 → 3.5 (truth-sync)
- Culture & Org / Education: 1.0 → 2.5 (SECURITY.md now accurate)
EOF
)"
```

---

## Risk assessment per patch

### 🟢 `gitleaks.toml` — LOW RISK
Pre-commit hook might now catch legitimate commits if team re-introduces
allowlisted hex strings. They were rotated, so this is the correct behavior.

### 🟢 `golangci.yml` — MEDIUM RISK
May surface new warnings on existing code. Two mitigation options:
1. **Incremental adoption:** uncomment `new-from-rev: main` line 110 to only
   fail on new code; existing warnings are reported but don't block.
2. **Batch cleanup:** run `golangci-lint run --fix ./...` to auto-fix most.

### 🟢 `SECURITY.md` — LOW RISK (technical), HIGH RISK (organizational)
Technical: file is text, no code impact. But: if customers have existing
contracts referencing SECURITY.md claims that this rewrite downgrades from
`OK` → `IN_PROGRESS`, that may require customer notification. **Recommend
legal review before push if VSP has customer SLAs referencing the file.**

### 🟡 `CI_FIXES.md` — MEDIUM RISK
Requires manual ci.yml edit. After applying, CI will fail on builds that
previously passed (because the previous checks didn't actually check). This
is **intentional** — it reveals hidden regressions. Expect 1-2 builds needing
code fix before main is green again.

### 🟡 `THREAT_MODEL_PATCH.md` — LOW RISK (technical)
Same organizational caveat as SECURITY.md — customer contracts may reference.

---

## What this bundle does NOT include

These are **out of scope** for Sprint 3.5; tackle in later sprints:

1. **Repo cleanup**: 700 MB binaries, 154 scripts — tracked as separate PR
2. **NTFS → ext4 migration**: infrastructure decision, requires downtime plan
3. **Frontend SEC-005/006/007**: Sprint 4, 3-week effort
4. **Vault integration**: Q3 2026 roadmap
5. **Anthropic key rotation**: manual action at Anthropic console (not a file)
6. **Tenant isolation audit remediation**: requires reading 10 query callers

---

## Verification checklist after apply

After committing, verify each of these in GitHub:

- [ ] CI `.github/workflows/ci.yml` → `ui-check` → `Check innerHTML XSS` step
      shows actual issue count (not "passed ✓" by default)
- [ ] CI `ui-check` → `Check localStorage token` step shows count (e.g. "22"),
      not grep of comments
- [ ] CI `security` → `gosec` step excludes only 5 rules (not 10)
- [ ] CI `ui-check` → `Check CSP middleware integrity` step verifies 5 directives
- [ ] `golangci-lint` job passes with 18 linters enabled
- [ ] `gitleaks` catches a fake `sk-ant-api03-<fake>` commit in a test branch
- [ ] SECURITY.md preview on GitHub shows "IN_PROGRESS" status on localStorage
- [ ] THREAT_MODEL.md query count reads "82/92", not "59/59"

---

## DSOMM score delta

| Dimension | Before | After Sprint 3.5 | Sprint 4 target |
|-----------|-------:|-----------------:|----------------:|
| Static Analysis | 2.5 | 3.0 | 3.5 |
| Design (Threat Model) | 3.0 | 3.5 | 3.5 |
| Education (Docs) | 1.0 | 2.5 | 3.0 |
| Secrets Management | 2.0 | 2.5 | 3.0 |
| **Average** | **2.95** | **3.20** | **3.5** |

---

## Questions before apply?

1. Does VSP have customer contracts referencing SECURITY.md? → legal review
2. Is `main` protected with required status checks? → new CI checks will
   block merges for ~24h while cleanup PRs catch up
3. Who reviews the PR? → assign both security lead + product owner (SECURITY.md
   edits affect product marketing claims)

If any of these are uncertain, hold the PR in draft and discuss first.
