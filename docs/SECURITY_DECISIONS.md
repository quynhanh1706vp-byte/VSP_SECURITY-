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

**Decision: [REVOKE / DEFER]**

**Rationale:** [User explanation]

**Next review date:** [Date]

**Owner:** [Name]
