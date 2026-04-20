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
