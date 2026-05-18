# VSP Risk Register

**Last reviewed:** 2026-05-08
**Owner:** Compliance + Engineering
**Reviewed at:** every quarter; emergency review on incident or external finding.

This register lists known risks to the VSP platform with current
mitigation, residual likelihood / impact, and review cadence. It is
the artefact a 3PAO will request first; the goal is to demonstrate
that we have *seen* the risks rather than to claim none exist.

Likelihood: 1 (rare) – 5 (almost certain). Impact: 1 (negligible) – 5
(catastrophic). Risk score = L × I.

---

| ID | Risk | L | I | Score | Current mitigation | Residual | Owner | Review |
|----|------|--:|--:|------:|--------------------|----------|-------|--------|
| **R-001** | JWT signing key compromise | 2 | 5 | 10 | Vault-backed rotation (15-min poll); dual-secret window; UEBA-driven auto session revoke | Low | Eng | quarterly |
| **R-002** | Postgres credential leak | 2 | 5 | 10 | Vault-stored DSN; pgxpool BeforeAcquire enforces tenant scope via RLS | Medium | Eng | quarterly |
| **R-003** | Cross-tenant data leak via unscoped query | 1 | 5 | 5 | Postgres RLS on 9 tables; KPI watchdog flags unscoped queries; CODEOWNERS reviews on all DB-touching code | Low | Eng | quarterly |
| **R-004** | Audit chain tampering | 1 | 5 | 5 | SHA-256 hash chain; `/api/v1/audit/verify` walks chain; `CHAIN_BROKEN` events fire watchdog → KPI sanity 409 | Very low | Eng | semi-annual |
| **R-005** | Supply-chain attack on dependency | 3 | 4 | 12 | go.sum pinned; cosign verify on container images; SLSA L3 attestations; OpenSSF Scorecard CI; trivy + grype + osvscanner + retirejs in pipeline | Medium | Eng | continuous |
| **R-006** | Third-party scanner false positive cascade | 3 | 2 | 6 | EPSS/KEV enrichment ranks; classifyVerifyFailure 7-state taxonomy (no "every-failure-is-tampered"); finding-level VEX | Low | Eng | continuous |
| **R-007** | Vietnam Decree 53/2022 cross-border data violation | 2 | 5 | 10 | Per-tenant residency binding; middleware returns 451 + audit row on cross-region; gateway region declared via `VSP_REGION` | Low | Compliance | quarterly |
| **R-008** | GDPR Art.17 erasure non-compliance | 2 | 4 | 8 | DSAR endpoint + 30-day grace + token-confirm + cancellable; cascading delete worker; audit trail of every erasure | Low | Compliance | quarterly |
| **R-009** | Public DoS on gateway | 3 | 3 | 9 | Per-tenant rate limit; sliding-window IP lockout (10min × 20 fails × 15min); HPA autoscaling + PDB; oversize body cap 10MB | Medium | Eng | continuous |
| **R-010** | Phishing / credential stuffing | 4 | 3 | 12 | HIBP breached-password check; WebAuthn + TOTP; account lockout; UEBA impossible-travel detection | Medium | Eng | continuous |
| **R-011** | Privileged user account compromise | 2 | 5 | 10 | Admin role gated by both RBAC + MFA; admin actions audit-logged; session anomaly auto-revoke; CODEOWNERS for all admin handlers | Medium | Sec | quarterly |
| **R-012** | Compliance documentation drift | 4 | 2 | 8 | KPI sanity endpoint asserts framework mappings load; quarterly improvement report regenerates evidence bundle; FEATURE_INVENTORY.md verified each release | Low | Compliance | quarterly |
| **R-013** | Helm chart misconfiguration in customer deployment | 3 | 3 | 9 | values.yaml restrictive defaults (non-root, read-only FS, drop ALL caps); deploy/helm/templates/networkpolicy.yaml DNS-only egress; Helm test rendering in CI | Medium | Eng | per-release |
| **R-014** | RLS policy bypass via owner role in production | 1 | 5 | 5 | Documented in deploy runbook: prod requires non-owner `db_app` role; KPI sanity tests verify policy presence | Low | Eng | quarterly |
| **R-015** | Cosign-API binary unavailable | 4 | 1 | 4 | classifyVerifyFailure distinguishes `unavailable` vs `tampered`; degraded operation does not block scans | Negligible | Eng | continuous |
| **R-016** | Webhook MITM via DNS hijack | 2 | 4 | 8 | SPKI cert pinning with backup keys; HMAC-SHA256 signing of body; DLQ retry with exponential backoff | Low | Eng | quarterly |
| **R-017** | DSAR / erasure request floods | 2 | 2 | 4 | Per-tenant rate limit on DSR endpoint; admin role required for erasure; 30-day grace allows mistake recovery | Low | Compliance | annual |
| **R-018** | KPI calibration regression (silent) | 3 | 3 | 9 | KPI sanity HTTP 409 release blocker; KPI watchdog 5-min interval writes `KPI_SANITY_FAILED` audit row; pinned tests in `internal/gate/engine_test.go` | Low | Eng | continuous |
| **R-019** | Vendor SaaS outage cascading to VSP (Stripe / VirusTotal) | 3 | 2 | 6 | Webhook DLQ retains failed deliveries; degraded operation when external dep down (status JSON reports it); fan-out worker uses circuit-breaker pattern | Low | Eng | continuous |
| **R-020** | Non-compliance with Luật ANM 2018 (Vietnam Cybersecurity Law 2018) | 2 | 5 | 10 | Data residency + audit chain + 72h reporting; legal review on every framework change | Low | Compliance + Legal | quarterly |
| **R-021** | Lack of operational pentest | 5 | 4 | 20 | **Open**: 3PAO engagement scheduled Q3 2026; until completion, treat 4.0 as aspirational | High | CISO | re-evaluate after pentest |
| **R-022** | Bug bounty triage backlog | 3 | 3 | 9 | **Open**: VDP published, intake operational; bounty platform contract pending. Mitigation: explicit ack SLA committed in policy doc | Medium | Sec + Business | quarterly |

---

## Risk acceptance & residual review

Risks tagged "Open" (R-021, R-022) have residual scores above the
organisation's acceptance threshold. Both require business / commercial
action that engineering cannot deliver alone:

- **R-021** — engaging a 3PAO firm at $80k-$150k for FedRAMP-style
  assessment (4-6 week engagement). Selecting from the shortlist in
  `docs/audit/3PAO_STATEMENT_OF_WORK.md` §7.

- **R-022** — onboarding to HackerOne or Intigriti at $5-15k/quarter
  + paid triage time. Code-side intake is ready; business signs the
  contract.

Until both are closed, any external claim of "fully audited" or
"4.0 certified" is unsupportable. The honest claim is:

> VSP is at DSOMM 3.9 with all code-side controls in place, and
> 4.0-attainable conditional on the two open business risks above.

This statement is the same one that appears in the public Trust
Center and the executive report — internal & external messaging
consistent.

---

## Review history

| Date | Reviewer | Changes |
|------|----------|---------|
| 2026-05-08 | Engineering + Compliance | Initial register, 22 entries |
| _next review_ | _Q3 2026_ | _to be filled_ |
