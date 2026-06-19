# Security Policy — VSP Security Platform

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 1.x.x   | ✅ | Actively maintained |
| < 1.0   | ❌ | Pre-release, no security support |

## Reporting a Vulnerability

**DO NOT** file public GitHub issues for security vulnerabilities.

### Preferred method: GitHub Security Advisory

1. Go to [Security tab](https://github.com/quynhanh1706vp-byte/VSP_SECURITY-/security)
2. Click **"Report a vulnerability"**
3. Fill in details including reproduction steps

### Alternative: Encrypted email

- **To**: soc@agency.gov
- **Subject**: `[SECURITY] VSP Security Platform — <brief description>`
- **PGP key**: Available on request

### What to include

- **Severity estimate** (CRITICAL / HIGH / MEDIUM / LOW)
- **Affected component** (BE, API, FE, CI/CD, Docker)
- **Reproduction steps** (minimal PoC)
- **Impact analysis** (what can an attacker do?)
- **Suggested fix** (if any)

### Response SLA

| Severity | Initial response | Fix target |
|----------|------------------|------------|
| CRITICAL | 4 business hours | 24 hours |
| HIGH     | 1 business day   | 7 days    |
| MEDIUM   | 3 business days  | 30 days   |
| LOW      | 7 business days  | 90 days   |

## Security Controls

### Continuous scanning (automated)

- **SAST**: CodeQL + semgrep (OWASP Top 10 packs) on every PR
- **SCA**: Trivy FS scan + govulncheck on every PR
- **Secrets**: gitleaks on every push
- **IaC**: Terrascan on Terraform files
- **Supply chain**: All GitHub Actions pinned to SHA (SLSA L2)
- **CSP**: Regression guard against `unsafe-inline`/`unsafe-eval`
- **postMessage**: Origin check enforcement (allowlist-based)
- **Dependency**: Dependabot alerts enabled

### Runtime hardening

- **Container**: Non-root user (uid ≥ 1000) in all Dockerfiles
- **Network**: Egress controls via workflow allowlist
- **Secrets**: Environment-based, no hardcoded credentials
- **HTTPS**: TLS 1.2+ enforced, HSTS enabled
- **Auth**: JWT Bearer tokens, MFA support (TOTP)
- **RBAC**: Role-based (admin/analyst/dev/auditor) + tenant isolation

### Code-level defenses

- **XSS**: All user-data rendered via `__esc()` helper or `textContent`
- **SQL injection**: Parameterized queries only (no string concat)
- **CSRF**: Token-based for state-changing endpoints
- **BOLA**: Tenant-scoped queries — all `WHERE id = ? AND tenant_id = ?`
- **Rate limiting**: Documented per endpoint in [openapi.yaml](./api/openapi.yaml)

## Compliance Frameworks

- **NIST SP 800-53 Rev 5** — Target: FedRAMP Moderate
- **NIST SP 800-171** — CMMC Level 2 aligned
- **TT13/2023** (Vietnam MIC Circular) — Full compliance target
- **OWASP ASVS 4.0** — Level 2
- **CIS Docker Benchmark 1.6** — Containers hardened

## Scope

### In scope
- All code in this repository
- Production deployment at `https://vsp.agency.gov`
- Staging at `https://staging.vsp.gov`
- Container images in GHCR

### Out of scope
- Third-party dependencies (report to maintainers upstream)
- Social engineering, physical access
- Denial-of-service against staging (permitted with notice)

## Recognition

Responsible disclosure earns:
- Credit in release notes (opt-in)
- Listing in `SECURITY_HALL_OF_FAME.md`
- Potential bounty for CRITICAL/HIGH (discretionary)

---

**Last updated**: 2026-04-24
**Policy version**: 1.0
**Maintainer**: VSP Security Team <soc@agency.gov>
