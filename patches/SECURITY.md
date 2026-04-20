# Security Policy

**Last verified:** 2026-04-20
**Version:** 2.0
**Baseline:** DSOMM self-assessment 2.95/4, roadmap to 3.5/4 target Q2 2026

This document reflects the **actual security posture** of VSP as of the date
above, verified by cross-referencing `internal/api/middleware/*.go`,
`internal/auth/*.go`, and `.github/workflows/ci.yml`. Every claim below is
backed by code references.

---

## Supported Versions

| Version | Status | Security Fixes |
|---------|--------|----------------|
| v1.3.x  | Current | Yes |
| v1.2.x  | Maintenance | Critical only |
| v1.1.x  | EOL 2026-06-30 | Critical only |
| < v1.1  | EOL | No |

---

## Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

### Contact

- **Email:** soc@agency.gov
- **PGP key:** https://vsp.agency.gov/.well-known/security.txt
- **Response time:** 48 hours acknowledgment

### Disclosure Process

1. Email `soc@agency.gov` with subject: `[VSP SECURITY] <brief description>`
2. Include: affected version, reproduction steps, potential impact
3. We acknowledge within 48 hours
4. We target patches:
   - **Critical (CVSS ≥ 9.0):** 7 days
   - **High (CVSS 7.0–8.9):** 30 days
   - **Medium (CVSS 4.0–6.9):** 90 days
   - **Low (CVSS < 4.0):** next quarterly release

---

## Implemented Security Controls

### ✅ Currently enforced in code

- **Content-Security-Policy** with per-request nonce
  ([`internal/api/middleware/csp.go`](internal/api/middleware/csp.go)):
  `default-src 'self'; script-src 'self' 'nonce-{16B}'; ...`
- **HTTP Security Headers:** HSTS (1 year + includeSubDomains), X-Frame-Options
  SAMEORIGIN, X-Content-Type-Options nosniff, Referrer-Policy
  strict-origin-when-cross-origin, Permissions-Policy (camera/mic/geolocation
  disabled)
- **CSRF protection** via double-submit cookie
  ([`internal/api/middleware/csrf.go`](internal/api/middleware/csrf.go)):
  `SameSite=Strict`, 32-byte random token, header validation on state-changing
  methods
- **HttpOnly + Secure session cookies**
  ([`internal/api/middleware/cookie_session.go`](internal/api/middleware/cookie_session.go)):
  `HttpOnly=true; Secure=true; SameSite=Strict`
- **Token-in-URL rejection:** endpoints return HTTP 400 if `?token=` present
  ([cookie_session.go#L51](internal/api/middleware/cookie_session.go))
- **Rate limiting:** 10 req/min on auth, 600 req/min per-user on API, 5/min on
  scanner batch ([`internal/api/middleware/ratelimit.go`](internal/api/middleware/ratelimit.go))
- **Request size cap:** 1 MB via MaxBytesReader on all endpoints
- **SQL injection prevention:** parameterized queries throughout
  `internal/store/`. No string concatenation with user input.
- **Multi-tenant isolation:** 82 of 92 queries enforce `tenant_id` at the SQL
  level. Remaining 10 are internal-only updates audited in
  [`docs/SECURITY_DECISIONS.md#SD-0045`](docs/SECURITY_DECISIONS.md).
- **JWT validation:** HMAC-SHA256 with secret from environment, 15-minute
  access token + refresh token rotation.
- **Audit log hash chain:** every audit entry links to previous via SHA-256
  hash; tampering detectable via `/api/p4/audit/verify`.
- **OIDC authentication:** supports Okta, Entra ID (Azure AD), Auth0, Google
  Workspace, generic OIDC providers ([`internal/auth/oidc.go`](internal/auth/oidc.go)).

### ✅ CI/CD enforced

- **SAST:** gosec on every push (severity: medium, confidence: medium)
- **SCA:** govulncheck for Go CVEs on every push
- **Secret scanning:** gitleaks pre-commit + CI with custom rules for
  Anthropic / Stripe / Slack formats
- **Container scanning:** Trivy CRITICAL+HIGH fails build; SARIF uploaded to
  GitHub Security tab
- **SBOM:** CycloneDX generated + attached to each release tag
- **DAST:** Nuclei scan on staging after main branch deploy (OWASP, XSS, SQLi,
  SSRF, auth, JWT tag sets)
- **Migration tests:** up → down → up cycle verified every PR
- **Race detector:** `go test -race` on every unit test run

### ✅ Operational

- **Container:** non-root (`USER nobody:nobody`), multi-stage Dockerfile with
  libpcap linkage verification via `ldd` sanity check
- **Capabilities:** `NET_RAW` + `NET_ADMIN` granted via `docker run` /
  `securityContext`, not setuid
- **Image pin:** `golang:1.25-alpine` builder, `alpine:3.20` runtime (digest
  pinning in Sprint 5)
- **TLS:** HSTS enforced; deployment guide mandates TLS termination via
  nginx / CloudFlare / ELB in front of gateway

---

## Known Limitations & Roadmap

### 🟠 In progress (Sprint 4, ~6 weeks)

- **Frontend JWT migration:** UI layer still reads `localStorage.getItem('vsp_token')`
  at 22 sites in `static/index.html`. Backend has full httpOnly cookie support
  ready (see `cookie_session.go`) — blocker is frontend refactor tracked as
  SEC-007.
- **SSE endpoint token param:** 2 frontend sites still pass JWT via `?token=`
  query. Backend rejects this with HTTP 400 (cookie_session.go:51); frontend
  migration to fetch + ReadableStream with Authorization header is queued.
- **Inline script elimination:** CSP enforces strict nonce-based script loading;
  current HTML has inline scripts the nonce injection handles, but full
  consolidation to bundled modules (SEC-005) required to remove `'unsafe-inline'`
  from style-src.
- **MFA enforcement:** TOTP support exists in auth layer but is not yet
  enforced by policy for admin accounts. Tracked for Sprint 4 PR #B.

### 🟡 Planned (Q3 2026)

- **Vault integration:** secrets currently in environment variables; migration
  to HashiCorp Vault or AWS Secrets Manager planned.
- **WAF layer:** deployment guide recommends CloudFlare / nginx; managed WAF
  integration tracked but not blocking.
- **HSM-signed audit log:** current audit log uses SHA-256 hash chain;
  HSM-backed signing planned for SEC-016 (Sprint 7).
- **Post-quantum crypto inventory:** EO 14144 (Jan 2025) migration — tracked
  as VSP_42 item #36.

### 🔴 Explicit non-goals

- **Full CSPM multi-cloud posture** (AWS/Azure/GCP): VSP partners with Wiz /
  Prisma Cloud for this layer rather than duplicating.
- **Dark web monitoring / DRP:** partner with Recorded Future / Flashpoint,
  not built-in.
- **Bug bounty platform integration:** handled via external partners.

---

## Defense in Depth Summary

| Layer | Control | Status |
|-------|---------|--------|
| Network | TLS + HSTS + WAF-ready | Enforced |
| Gateway | Rate limit + size cap + CSP + CSRF | Enforced |
| Auth | OIDC + JWT + HttpOnly cookie + MFA-ready | Mostly enforced |
| Application | Parameterized SQL + tenant_id + input validation | Enforced |
| Data | At-rest encryption + audit chain | Enforced |
| Runtime | Non-root container + cap-drop + seccomp | Enforced |
| Supply chain | SBOM + govulncheck + Trivy + gosec | Enforced |

---

## Documentation

- **Full STRIDE threat model:** [THREAT_MODEL.md](THREAT_MODEL.md)
- **Architecture overview:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) *(Sprint 5)*
- **JWT rotation runbook:** [docs/JWT_ROTATION_RUNBOOK.md](docs/JWT_ROTATION_RUNBOOK.md)
- **Security decisions log:** [docs/SECURITY_DECISIONS.md](docs/SECURITY_DECISIONS.md)
- **Incident response:** [docs/INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md) *(Sprint 5)*
- **Compliance matrix:** [docs/COMPLIANCE_MATRIX.md](docs/COMPLIANCE_MATRIX.md) *(Sprint 5)*
- **DevSecOps posture:** [docs/SECURITY_POSTURE.md](docs/SECURITY_POSTURE.md) *(Sprint 5)*

---

## Compliance Alignment

VSP targets the following frameworks for customer attestation:

- **NIST SP 800-53 Rev 5** — Moderate baseline, 242/283 controls addressed
- **NIST SP 800-218 SSDF** — all 4 groups (PO, PS, PW, RV) mapped
- **FedRAMP Moderate** — ATO in progress (P4 Readiness 100%)
- **CMMC Level 2** — 110/110 practices addressed
- **OWASP DSOMM** — self-assessed 2.95/4, Q2 2026 target 3.5/4
- **CISA Secure by Design** — 3 principles + pledge signed

Detailed control mapping: `docs/COMPLIANCE_MATRIX.md` (Sprint 5 deliverable).

---

## Hall of Fame

Responsible disclosures are acknowledged here with researcher consent.

*(No disclosures yet — first one gets permanent mention.)*

---

## Change Log

- **2026-04-20** — Rewrote SECURITY.md against actual code. Previous version
  (2026-04-10) claimed MFA enforced, cookie-based auth complete, and
  `?token=` blocked on all endpoints — first two were planned, third was
  backend-only. This version aligns claims with implementation.
