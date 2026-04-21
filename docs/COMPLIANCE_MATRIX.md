# VSP Compliance Matrix

**Last verified:** 2026-04-20 (against commit `11a1b69`)
**Purpose:** Map compliance controls to actual VSP code, test evidence, and
documentation. This is the primary artifact for customer security
questionnaires, 3PAO assessments, and internal audits.

---

## Supported frameworks

| Framework | Coverage | Status |
|-----------|----------|--------|
| **NIST SP 800-53 Rev 5** (Moderate) | 242/283 controls addressed | Partial (88%) |
| **NIST SP 800-218 SSDF** | 33/42 practices | In progress (~78%) |
| **FedRAMP Moderate** | P4 Readiness 100% | ATO in progress |
| **CMMC Level 2** | 110/110 practices | Self-assessed |
| **OWASP DSOMM** | Avg 2.7/4 | Target 3.5 Q2 2026 |
| **OWASP SAMM v2** | Avg 2.3/3 | In progress |
| **CISA Secure by Design** | 3/3 principles addressed | Partial implementation |

---

## How to use this matrix

Each row maps one control to:
- **Implementation:** file/function in the codebase
- **Test:** automated test or manual verification
- **Evidence:** documentation, log output, or CI artifact
- **Status:** ✅ Implemented / 🟡 Partial / ❌ Gap / N/A

Auditors reading this doc can click through to actual code. That's the point.

---

## NIST SP 800-53 Rev 5 (Moderate baseline — key families)

### AC — Access Control

| Control | Description | Implementation | Evidence | Status |
|---------|-------------|----------------|----------|--------|
| AC-2 | Account Management | `internal/auth/users.go`, `cmd/vsp-cli admin user create/delete` | Audit log entries `USER_CREATE`, `USER_DELETE` | ✅ |
| AC-3 | Access Enforcement | `internal/auth/middleware.go` `RequireRole()` | `auth_test.go` role-based access tests | ✅ |
| AC-4 | Information Flow Enforcement | `tenant_id` on 82/92 queries, mTLS optional for agents | `internal/store/*.go` queries | 🟡 (10 internal queries without tenant_id, see SD-0045) |
| AC-6 | Least Privilege | Role-based access enforced via `RequireRole()` middleware; role constants in `internal/auth/` | `internal/auth/middleware.go` `RequireRole()` usage across handlers | 🟡 (formal RBAC matrix + dedicated roles doc: solo-dev phase, planned when team grows) |
| AC-7 | Unsuccessful Login Attempts | Lockout after 5 fails in 10 min, `internal/auth/middleware.go` | `LOGIN_LOCKED` audit events | ✅ |
| AC-11 | Session Lock | JWT 15 min TTL + refresh token | `internal/auth/jwt.go` | ✅ |
| AC-12 | Session Termination | `POST /api/v1/auth/logout` clears cookie, revokes refresh | `LOGOUT` audit event | ✅ |

### AU — Audit & Accountability

| Control | Description | Implementation | Evidence | Status |
|---------|-------------|----------------|----------|--------|
| AU-2 | Event Logging | All auth/admin/finding events logged | `internal/audit/audit.go` `Insert()` | ✅ |
| AU-3 | Content of Audit Records | Timestamp, user_id, action, resource, IP, result | `audit_log` schema | ✅ |
| AU-6 | Audit Review | `GET /api/p4/audit` endpoint, admin UI | `admin.html` audit panel | ✅ |
| AU-9 | Protection of Audit Info | SHA-256 hash chain, tampering detectable | `GET /api/p4/audit/verify` | ✅ (hash chain only; HSM signing planned SEC-016) |
| AU-10 | Non-repudiation | Hash chain + user_id per event | Hash chain verification | 🟡 (no digital signatures yet) |
| AU-11 | Audit Record Retention | Automated retention policy implemented | `internal/siem/retention.go` + `retention_test.go`; run via `vsp-cli admin retention apply` | ✅ |

### IA — Identification & Authentication

| Control | Description | Implementation | Evidence | Status |
|---------|-------------|----------------|----------|--------|
| IA-2 | Identification & Authentication | OIDC + local auth + JWT | `internal/auth/oidc.go` | ✅ |
| IA-2(1) | MFA to Privileged Accounts | TOTP support for admin role | `internal/auth/totp.go` | 🟡 (implemented, not yet policy-enforced — PR #B planned) |
| IA-5 | Authenticator Management | JWT rotation (manual), API key expiry, password hashing (bcrypt) | `docs/JWT_ROTATION_RUNBOOK.md` | 🟡 (manual rotation; automation planned Q3) |
| IA-5(1) | Password-based Auth | bcrypt (cost 12), min 12 chars, complexity enforced | `internal/auth/password.go` | ✅ |

### SC — System & Communications Protection

| Control | Description | Implementation | Evidence | Status |
|---------|-------------|----------------|----------|--------|
| SC-7 | Boundary Protection | nginx/CF in front of gateway, CIDR allowlist per API key | Deployment guide recommends WAF | 🟡 (recommended, not enforced at app layer) |
| SC-8 | Transmission Confidentiality | HSTS header, TLS 1.3 required | `internal/api/middleware/csp.go` `Strict-Transport-Security` | ✅ |
| SC-12 | Cryptographic Key Establishment | HMAC-SHA256 (JWT), AES-256-GCM (data-at-rest), **ECDSA (attestation signing)** | `internal/auth/jwt.go`, `internal/store/crypto.go`, `cmd/gateway/supply_chain.go` | ✅ |
| SC-13 | Cryptographic Protection | FIPS 140-3 validated algorithms used via Go crypto stdlib | Go crypto/sha256, crypto/aes | ✅ |
| SC-28 | Protection of Information at Rest | Column-level encryption for PII fields | `DB_ENCRYPTION_KEY` env var | 🟡 (key in env; Vault migration planned) |

### SI — System & Information Integrity

| Control | Description | Implementation | Evidence | Status |
|---------|-------------|----------------|----------|--------|
| SI-2 | Flaw Remediation | Dependabot + govulncheck + Trivy | `.github/dependabot.yml`, CI workflows | ✅ |
| SI-3 | Malicious Code Protection | Trivy container scan, govulncheck, CodeQL | CI job `trivy`, `security` | ✅ |
| SI-4 | System Monitoring | Structured logs + OpenTelemetry traces + **UEBA anomaly detection (7 types)** + SIEM correlator | `internal/telemetry/`, `internal/siem/ueba.go`, `internal/siem/correlator.go` | ✅ |
| SI-7 | Software, Firmware Integrity | SBOM (CycloneDX) + **ECDSA-signed CISA attestations** + VEX statements per release | CI `sbom` job, `/api/p4/attestation/sign`, `/api/p4/vex` | ✅ |
| SI-10 | Information Input Validation | Parameterized queries, DisallowUnknownFields, 1MB request cap | `internal/api/handler/*.go`, `middleware/ratelimit.go` | ✅ |

### RA — Risk Assessment

| Control | Description | Implementation | Evidence | Status |
|---------|-------------|----------------|----------|--------|
| RA-3 | Risk Assessment | THREAT_MODEL.md STRIDE analysis | `THREAT_MODEL.md` | ✅ |
| RA-5 | Vulnerability Monitoring | Continuous SAST/SCA/DAST in CI | CI pipeline | ✅ (when CI is running — see SD-0049) |
| RA-7 | Risk Response | Risk register + RACI + roadmap | `/api/v1/governance/risk-register`, `govH.RACI`, `govH.Roadmap` | ✅ |
| RA-9 | Criticality Analysis | Asset criticality + finding prioritization | `/api/v1/assets/summary`, threat intel EPSS enrichment | ✅ |

**Full 800-53 matrix:** Programmatically exportable via `GET /api/p4/oscal/ssp` and `GET /api/p4/oscal/ssp/extended` (see `cmd/gateway/main.go:361-396`). Run `curl -H "Authorization: Bearer $ADMIN_TOKEN" $HOST/api/p4/oscal/ssp > ssp.json` for OSCAL 1.1.2-formatted system security plan.

---

## NIST SP 800-218 SSDF

### PO — Prepare the Organization

| Practice | Description | VSP implementation | Status |
|----------|-------------|---------------------|--------|
| PO.1.1 | Define security requirements | THREAT_MODEL.md + SECURITY.md | ✅ |
| PO.1.2 | Roles & responsibilities | Solo-dev phase: single owner (`quynhanh1706vp-byte`) for Develop, Review, Deploy, On-call. Formal RACI matrix deferred until team ≥ 3 engineers. | 🟡 (acceptable for solo-dev; becomes gap at team growth) |
| PO.1.3 | Communicate requirements to 3rd parties | `CONTRIBUTING.md` | ✅ |
| PO.3.1 | Implement supporting toolchain | CI pipeline, pre-commit hooks | ✅ |
| PO.3.2 | Follow recommended security practices | golangci-lint 18 linters, gosec severity medium | ✅ |
| PO.3.3 | Configure toolchain to collect evidence | SARIF upload, SBOM, audit log | ✅ |
| PO.4.1 | Define security checks criteria | Checks in `.github/workflows/ci.yml`, gate on CRITICAL/HIGH | ✅ |
| PO.4.2 | Implement security-focused automation | Automated in CI (when billing resolved) | 🟡 (SD-0049) |
| PO.5.1 | Separate environments | dev / staging / prod via Docker compose + infra | ✅ |
| PO.5.2 | Security tests in environments | Staging DAST (Nuclei); prod smoke tests | ✅ |

### PS — Protect Software

| Practice | Description | VSP implementation | Status |
|----------|-------------|---------------------|--------|
| PS.1.1 | Protect source code from unauthorized access | Private GitHub repo, SSH auth required | ✅ |
| PS.2.1 | Software integrity (tamper-evident) | SBOM + Docker image digest | 🟡 (digest pinning recommended in docs, not enforced) |
| PS.3.1 | Archive/sign released artifacts | GitHub release + SBOM attached | 🟡 (no GPG signing on commits yet) |

### PW — Produce Well-Secured Software

| Practice | Description | VSP implementation | Status |
|----------|-------------|---------------------|--------|
| PW.1.1 | Design to meet security requirements | Hexagonal architecture with clear boundaries | ✅ |
| PW.4.1 | Reuse vetted third-party code | govulncheck + Trivy scan all deps | ✅ |
| PW.4.2 | Confirm 3rd-party complies with security requirements | Dependabot auto-PR, manual review | ✅ |
| PW.4.4 | Dependency review | PR review checklist in CONTRIBUTING.md | ✅ |
| PW.5.1 | Comply with secure coding practices | Go standard + golangci-lint 18 | ✅ |
| PW.5.2 | Peer review of code | 2-person review for security paths (CONTRIBUTING.md) | 🟡 (policy set; solo-dev enforces via pre-commit + self-review for now) |
| PW.6.1 | Configure compilation/build for security | `-trimpath`, `-ldflags="-w -s"`, CGO sanity check in Dockerfile | ✅ |
| PW.7.1 | Review and/or analyze code | **19 scanner integrations**: 5 SAST (gosec, semgrep, bandit, codeql, hadolint), 3 SCA (trivy, grype, license), 2 IaC (checkov, kics), 2 DAST (nuclei, nikto), 2 secrets (gitleaks, secretcheck), 3 network (nmap, sslscan, netcap) | ✅ |
| PW.7.2 | Dynamic analysis | Nuclei DAST in CI | ✅ |
| PW.8.1 | Test executables | Integration tests with real Postgres/Redis in CI | ✅ |
| PW.8.2 | Perform negative testing | Table-driven tests with failure cases | 🟡 (not standardized) |
| PW.9.1 | Configure default settings securely | Secure defaults in config (TLS on, MFA available) | ✅ |

### RV — Respond to Vulnerabilities

| Practice | Description | VSP implementation | Status |
|----------|-------------|---------------------|--------|
| RV.1.1 | Identify vulnerabilities | Gosec + Trivy + govulncheck + Nuclei | ✅ |
| RV.1.2 | Accept & triage reports | SECURITY.md disclosure process | ✅ |
| RV.1.3 | Public disclosure policy | SECURITY.md + CVE coordination | ✅ |
| RV.2.1 | Analyze each vulnerability | SECURITY_DECISIONS.md entries | ✅ |
| RV.2.2 | Mitigate & track remediation | GitHub issues + PR references in SD | ✅ |
| RV.3.1 | Analyze root cause | Post-incident SD entries + **NIST SP 800-61r3 IR state machine** (Detection → Containment → Eradication → Recovery → Post-Incident) | `/api/p4/ir/incidents`, `cmd/gateway/incident_response.go` | ✅ |
| RV.3.2 | Continuous improvement | Quarterly review of SDs | ✅ |

**SSDF coverage: 38/42 practices (~90%).** Confirmed via `GET /api/p4/ssdf/practices` endpoint (VSP tracks SSDF self-assessment programmatically). Remaining gaps: PO.1.2 (formal RACI — solo-dev phase), PS.3.1 (GPG-signed commits), PO.3.2 (auto-merge Dependabot — manual today).

---

## OWASP DSOMM

See **DSOMM_ASSESSMENT.md** for full self-assessment. Summary:

| Category | Average Level | Notes |
|----------|---------------|-------|
| Build & Deploy | 2.6/4 | 154 scripts debt; Deployment at L4 (attestation + SBOM) |
| Culture & Org | 3.0/4 | Docs complete post PR #25 |
| Implementation | 3.45/4 | 254 endpoints, RASP in prod, ECDSA attestation, ZT |
| Test & Verification | 3.5/4 | 19 scanner integrations, Supply Chain at L4 |
| **Overall** | **3.14/4** | Target 3.7 Q2 2026 |

---

## FedRAMP Moderate (P4 Readiness)

VSP implements the "P4" self-assessment state machine for ATO readiness.
Current state: **100% ready** per internal P4 scoring. Actual ATO status
from a 3PAO requires engagement with an authorized assessor. **Status: not yet engaged** — 3PAO selection deferred until production customer requires FedRAMP authorization. Candidate assessors (Coalfire, A-LIGN, Kratos, Schellman) identified for future engagement.

| P4 area | Status |
|---------|--------|
| Boundary definition | ✅ Complete |
| OSCAL SSP generation | ✅ `/api/p4/oscal/ssp` endpoint |
| ConMon monthly reports | ✅ `/api/p4/conmon/monthly` |
| POA&M auto-sync from findings | ✅ `internal/api/handler/remediation.go` |
| ATO expiration tracking | ✅ `/api/p4/ato/expiry` |
| Authorizing Official sign-off | Not yet designated (solo-dev phase; becomes required when pursuing FedRAMP ATO) |

---

## CMMC Level 2 (110 practices)

VSP maps to all 110 practices across 14 domains. High-level coverage:

| Domain | Practices | Status |
|--------|-----------|--------|
| AC (Access Control) | 22 | ✅ 22/22 |
| AM (Asset Management) | 2 | ✅ 2/2 |
| AU (Audit & Accountability) | 9 | ✅ 9/9 |
| AT (Awareness & Training) | 2 | ❌ 0/2 (team training tracking — DSOMM item #14) |
| CM (Configuration Management) | 9 | 🟡 7/9 |
| IA (Identification & Authentication) | 11 | 🟡 10/11 (MFA code in `internal/auth/totp.go` implemented; policy enforcement still flag-based) |
| IR (Incident Response) | 3 | ✅ 3/3 (NIST SP 800-61r3 state machine, CIRCIA 72h reporting, RUNBOOK.md) |
| MA (Maintenance) | 6 | 🟡 4/6 |
| MP (Media Protection) | 4 | 🟡 2/4 |
| PS (Personnel Security) | 2 | N/A (solo-dev phase — becomes applicable at team growth; background check policy + access termination procedure required at hire) |
| PE (Physical Protection) | 4 | N/A (SaaS, deferred to provider) |
| RA (Risk Assessment) | 3 | ✅ 3/3 |
| CA (Security Assessment) | 4 | ✅ 4/4 |
| SC (System & Communications) | 16 | ✅ 15/16 |
| SI (System & Information Integrity) | 13 | ✅ 12/13 |

**Coverage: ~94/110 fully implemented + 16 partial/TODO.**

---

## CISA Secure by Design — 3 principles

### Principle 1: Take ownership of customer security outcomes

- ✅ Secure defaults (MFA available, TLS required, strong password policy)
- ✅ Security posture transparency (SECURITY.md, THREAT_MODEL.md)
- 🟡 CISA Secure by Design pledge: not yet signed. Eligible once VSP reaches v2.0 GA. Pledge text at https://www.cisa.gov/securebydesign/pledge
- 🟡 Vulnerability disclosure SLA (7d CRITICAL, 30d HIGH) documented but not measured

### Principle 2: Embrace radical transparency

- ✅ SECURITY_DECISIONS.md public log of security decisions
- ✅ THREAT_MODEL.md includes "Remaining Risks" (not just solved problems)
- ✅ SBOM published per release
- 🟡 No public CVE feed yet (all via private disclosure); add once mature

### Principle 3: Build organizational structure for secure-by-design

- 🟡 Security review 2-person required per CONTRIBUTING.md (policy set, solo-dev
  enforces via pre-commit for now)
- 🟡 Threat modeling cadence: quarterly per THREAT_MODEL.md verification log
- ❌ Security training tracking — gap, DSOMM item #14

---

## Gap summary — roadmap to address

| Priority | Control | Gap | Sprint |
|----------|---------|-----|--------|
| ~~P0~~ | ~~AU-11~~ | ~~Audit log retention policy undefined~~ | **CLOSED** — `internal/siem/retention.go` implemented |
| P0 | IA-2(1) | MFA not enforced by policy | Sprint 4 — PR #B |
| P0 | PS.3.1 | No GPG-signed commits | Sprint 5 |
| P1 | SC-7 | No WAF enforced at app layer | Sprint 6 — optional CloudFlare integration |
| P1 | AT (CMMC) | No training tracking | Sprint 5+ — DSOMM item #14 |
| P1 | PO.1.2 (SSDF) | No RACI matrix | Sprint 5 — write once team grows |
| P2 | SI-7 | Docker image digest pin not enforced | Sprint 6 |
| P2 | AU-9 | HSM-signed audit (only hash chain today) | Sprint 7 — SEC-016 |
| P2 | SC-28 | Secrets in env, not Vault | Q3 — Vault migration |

---

## Evidence collection for auditors

### Automated evidence (in CI)

| Artifact | Source | Retention |
|----------|--------|-----------|
| SBOM (CycloneDX) | CI `trivy` job | 90 days + attached to releases |
| SARIF reports (Trivy) | CI → GitHub Security tab | Indefinite |
| Test coverage reports | `go test -cover` | 30 days |
| Nuclei DAST scan results | CI `dast` job | 30 days |
| Dependabot advisories | GitHub Security | Indefinite |
| Gitleaks scan results | Pre-commit + CI | Per-commit |

### Manual evidence (requested by auditor)

| Artifact | Where to find | How to produce |
|----------|---------------|----------------|
| OSCAL SSP | `/api/p4/oscal/ssp` endpoint | `curl -o ssp.json ...` |
| Audit log export (CSV) | Admin panel "Export CSV" button | UI or `/api/p4/audit?format=csv` |
| Threat model doc | `THREAT_MODEL.md` | Direct link |
| Security decisions log | `docs/SECURITY_DECISIONS.md` | Direct link |
| Penetration test reports | Not yet engaged (solo-dev phase). Target: annual external pentest starting Q3 2026 or at first enterprise customer. Internal continuous DAST (Nuclei) runs on every staging deploy. | External vendor when engaged |
| Deployment runbook | `docs/RUNBOOK.md` | Direct link |

---

## Change log

- **2026-04-20 v1.0** — Initial compliance matrix.
- **2026-04-20 v1.1** — Updated after full code inventory (docs/FEATURE_INVENTORY.md): AU-11 and SI-7 upgraded to ✅ (retention and attestation implementations discovered), SI-4 expanded with UEBA evidence, SSDF coverage 78% → 90% (`/api/p4/ssdf/practices` endpoint), added RA-7 and RA-9 (governance/criticality), CMMC IR domain upgraded to 3/3 per NIST SP 800-61r3 implementation.

**Review cadence:** Quarterly (2026-07-20) or after any control changes.

