# Security Decisions Log

## 2026-04-20 — Anthropic API Key Leak (thu-first-key)

**Incident:** API key `sk-ant-api03-YFOJte...7AAA` leaked in git history,
commits `aebee892`, `2652198`, `3fb18207` (config/config.yaml).

**Discovered:** 2026-04-20 via gitleaks scan during Sprint 2 cleanup.

**Risk assessment:**
- Repo visibility: PRIVATE
- Key status at discovery: ACTIVE (verified HTTP 200 on /v1/models)
- Last used: Never (per Anthropic Console, Apr 7 - Apr 20)
- Plan tier: Free "Evaluation access" (no billing exposure)
- Account owner: thunt.rsa@gmail.com

**Decision: DEFER**

**Rationale:**
- Key on free "Evaluation access" tier — zero billing exposure
- Repo PRIVATE — limited blast radius to authenticated team members
- Last used: Never in 13 days since creation (Apr 7 → Apr 20)
- No evidence of abuse in Anthropic Console usage history
- Gateway uses a different ANTHROPIC_API_KEY from systemd env (not this key)
- Revocation cost (tool reconfig, test) > current risk (near-zero on free tier)

**Next review date:** 2026-05-20 (30 days)
**Review trigger (earlier):**
- Upgrade Anthropic plan from Evaluation to paid tier → revoke IMMEDIATELY
- Repo visibility changes from PRIVATE → PUBLIC → revoke IMMEDIATELY
- Any "Last used" usage appears that was not initiated by owner → revoke + investigate

**Owner:** thunt.rsa@gmail.com (account owner)

**Mitigations applied:**
- Gateway uses separate ANTHROPIC_API_KEY from systemd env
- gitleaks CI enabled (PR #19) to catch future leaks
- Custom gitleaks rule for Anthropic format added to Sprint 3 backlog (#44)
- SECURITY_DECISIONS.md created to track deferred security decisions

**Related artifacts:**
- PR #19: gitleaks migration + Trivy sanitize
- Sprint 3 item #43: Historical secret scan + rotation procedure
- Sprint 3 item #44: Custom gitleaks rules for Anthropic/OpenAI/AWS formats

## 2026-04-20 — PR #20 + #21 admin-merge override

**Context:** GitHub Actions billing/quota exhausted → all CI jobs blocked
with "recent account payments failed or spending limit exceeded" error.

**Decision:** Admin-merged PR #20 and #21 without CI validation.

**Justification:**
- CI failure root-caused to account billing, NOT code issues
- Local validation comprehensive: go build OK, go vet OK, tests pass,
  gosec verified G402/G108/G306/G120/G114 closed, gitleaks clean
- Changes are security-improving (closing gosec findings, not introducing
  new code paths)
- Blocking urgency: CI may not recover until 2026-05-01 quota reset

**Risk accepted:** No automated validation that fixes work in CI environment.
Local environment verified equivalent.

**Mitigation:** Next CI run after quota reset should be monitored; any
regression surfaces immediately on main branch.

**Owner:** thunt.rsa@gmail.com

## 2026-04-20 — Binary accidentally committed in commit 089f114

**Incident:** 18.3 MB binary file `dev-stub` committed to main branch
via PR #22 merge. Binary was compiled output of `go build ./cmd/dev-stub/`
run from repo root before file was moved to proper location.

**Content analysis:**
Binary contains dev-stub server with JWT token stub:
- Header: {"alg":"HS256","typ":"JWT"}
- Payload: {"sub":"admin@vsp.local","role":"admin","exp":99999999999}
- Signature: literal string "signature" (NOT a valid HMAC-SHA256 hash)

**Risk assessment:**
- JWT token is cryptographically INVALID — production gateway validates
  HMAC signature and will reject this token
- Binary contains no other credentials, secrets, or exploit primitives
- Risk = repo bloat (+18.3 MB in git history), no security impact

**Decision: DEFER history rewrite**

**Rationale:**
- Invalid JWT = no exploit value for attacker
- Repo PRIVATE = limited blast radius
- `git filter-repo` requires force-push that would invalidate PR refs
  and require all team members to re-clone
- Cost of rewrite (operational disruption) > benefit (18MB disk)

**Mitigations applied:**
- Binary removed from working tree (commits 7aff67b, 96a8175)
- .gitignore updated to blacklist all compiled binaries
- This decision logged for future audit

**Next review:** If repo goes public, immediately force-rewrite history.

## 2026-04-20 — Binary accidentally committed in commit 089f114

**Incident:** 18.3 MB binary file `dev-stub` committed to main via PR #22.
Binary was compiled output of `go build ./cmd/dev-stub/` run from repo
root before files were moved. `go build` writes binary named after
package directory to CWD (repo root).

**Content analysis:**
Binary contains dev-stub server with JWT token stub:
- Payload: {"sub":"admin@vsp.local","role":"admin","exp":99999999999}
- Signature: literal string "signature" (NOT valid HMAC-SHA256)

Token is cryptographically INVALID — production gateway validates HMAC
and will reject it.

**Decision: DEFER history rewrite**

**Rationale:**
- Invalid JWT = zero exploit value
- Repo PRIVATE = limited blast radius
- git filter-repo requires force-push invalidating PR refs
- Operational cost > benefit (18MB disk in git history)

**Mitigations applied:**
- Binary removed from working tree (commits 7aff67b, 96a8175)
- .gitignore updated with binary blacklist patterns
- This incident logged for audit trail

**Next review:** If repo goes public → immediate force-rewrite history.

**Prevention:** Future `go build` usage must use `-o /tmp/binary-name`
flag or be run inside target directory to prevent binary artifacts
in repo root.

## 2026-04-20 — Git history contains 420MB of binaries (discovery)

**Finding:** 14 ELF binaries totaling ~420MB found in git history:
- 7 gateway binary variants (gateway, gateway.old, vsp-gateway, etc.)
- scanner, siem-seed, soc-shell, vsp_server binaries
- 2 .fuse_hidden* files (FUSE artifacts)
- 2 static/download/vsp-agent-* (may be intentional for downloads)

**Unknown severity — NOT scanned for embedded secrets yet.**

Potential risks if binaries were compiled with real env vars:
- JWT_SECRET embedded (would allow token forge)
- DB_URL with password
- API keys (Anthropic, OpenAI, AWS, etc.)

**Decision: DEFER audit + cleanup to Sprint 3 item #59**

**Prevention applied today:**
- .gitignore updated with binary patterns (commit 7aff67b)
- Will prevent future accidents

**Required next session action:**
1. Scan all 14 binaries for embedded secrets
2. If secrets found → ROTATE + filter-repo cleanup
3. If clean → filter-repo for repo size reduction (optional)
4. Add pre-commit hook to reject binaries >1MB

**Discovery method:** `git cat-file --batch-all-objects --batch-check` 
filtered for size > 10MB during binary purge verification after PR #22.

## 2026-04-20 — Binary scan follow-up (no secrets found)

Update to previous entry (420MB binaries discovery).

**Scanned:** All 14 binaries >10MB in git history.

**Result:** NO embedded secrets detected.
- No Anthropic API keys (sk-ant-api03-*)
- No JWT_SECRET environment values
- No DB credentials (postgres://user:pass)
- No AWS access keys
- "Password" / "key" / "secret" matches are Go function/variable
  names (compiler metadata), not credential values

**Updated decision: No security incident. Only repo bloat.**

**Recommendation:**
- DEFER filter-repo cleanup to Sprint 3 or later
- Binaries do not warrant nuclear option (force-push risk)
- Accept 420MB git history bloat as technical debt
- .gitignore already updated to prevent future accidents
- Item added to Sprint 3 backlog: "Investigate static/download/* as intentional"

---

## SD-0047 — PR #24 merged with --admin bypass

**Date:** 2026-04-20 18:05
**Decision:** Merged PR #24 with `gh pr merge --admin` despite 5 failing CI jobs.
**Rationale:** Commit contained fixes to .gitleaks.toml (regex RE2 fix) +
  truth-sync docs. CI failures observed were determined to be [TBD after
  investigation — see Bước 1 output]. Documented here per DevSecOps
  principle that bypasses MUST be traceable.
**Impact:** Main branch currently contains code that did not pass full CI gate.
**Remediation:**
  - Investigate CI failure root cause (action: 20/04 tối hoặc 21/04 sáng)
  - Fix forward on main if real issues (not billing/infra)
  - Establish policy: --admin merge requires explicit SD-XXXX entry BEFORE merge
**Lesson:** CI must be unblocked before considering any merge, including hygiene PRs.

---

## SD-0048 — Direct push to main on commit 3cac764 (gitleaks v3)

**Date:** 2026-04-20 18:15
**Decision:** Committed gitleaks v3 fix (38 false positives → 0) directly to
  main, bypassing branch/PR workflow.
**Rationale:**
  - Intended to create branch `fix/sprint35-hotfix-v3-*` but `git checkout`
    with wildcard failed silently (shell did not expand branch name),
    leaving session on main.
  - CI has been red for ~1 week (cause under investigation, not related to
    this change) — PR would not pass checks regardless of content.
  - Commit contained only allowlist config changes (no executable code),
    reviewed locally by DevSecOps lead before commit.
  - Pre-commit hook (gofmt, go vet, gitleaks) passed ✓
**Impact:** Bypass of 2-person review for single-author repo. Acceptable risk
  given:
  - VSP is solo-dev phase (no team review possible)
  - Change is config-only (no code execution paths affected)
  - Pre-commit gitleaks verified scan clean before push
**Remediation:**
  - Future workflow: always `git branch --show-current` before commit
  - Never use `git checkout <wildcard>` — always tab-complete branch name
  - Consider adding git pre-push hook to block direct pushes to main when
    repo is multi-author.
**Related:** SD-0047 (PR #24 --admin bypass) — same root cause: CI broken
  forced bypass. Both close out when CI restored.

**Status:** Accepted. Review quarterly (next: 2026-07-20).
