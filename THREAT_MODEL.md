# VSP Security Platform — Threat Model (STRIDE)

**Version:** 1.0 | **Date:** 2026-04-10 | **Method:** STRIDE

## System Overview

VSP is a multi-tenant vulnerability scanning platform serving government agencies.
Key components: API Gateway, Scanner workers, PostgreSQL, Redis, SIEM engine.

## Trust Boundaries

    [Browser] --HTTPS--> [API Gateway :8921] --> [PostgreSQL]
                                  |               [Redis]
                                  +-> [Scanner workers]
                                  +-> [SIEM engine]

## STRIDE Analysis

### S — Spoofing

| Threat | Mitigation | Status |
|--------|------------|--------|
| JWT forgery | HMAC-SHA256, secret from env | OK |
| Token theft via XSS | httpOnly cookie (CWE-312) | OK |
| Token in SSE/WS URL | Removed ?token= from all URLs | OK |
| Brute force login | 10 req/min + lockout after 5 fails | OK |
| Session fixation | New JWT issued on every login | OK |
| CAC/PIV bypass | OIDC validation, no Referer bypass | OK |

### T — Tampering

| Threat | Mitigation | Status |
|--------|------------|--------|
| SQL injection | Parameterized queries only | OK |
| Mass assignment | DisallowUnknownFields + 1MB cap | OK |
| Audit log tampering | Hash-chain verification | OK |
| Finding dedup bypass | ON CONFLICT DO UPDATE | OK |
| Profile enum bypass | Enum validation BE + openapi | OK |

### R — Repudiation

| Threat | Mitigation | Status |
|--------|------------|--------|
| Login/logout not logged | LOGIN_OK, LOGOUT, LOGIN_FAILED audit | OK |
| Scan trigger not tracked | Run ID + tenant + user in audit | OK |
| Admin actions untracked | Audit entry on user create/delete | OK |

### I — Information Disclosure

| Threat | Mitigation | Status |
|--------|------------|--------|
| Version in /health | Removed from public response | OK |
| Stack traces in errors | Generic error messages only | OK |
| Token in URL | Cookie-based, ?token= blocked (400) | OK |
| Secrets in repo | pre-commit gitleaks + CI gitleaks | OK |
| User enumeration | Generic "invalid credentials" message | OK |
| Tenant data leak | tenant_id on 59/59 queries (audited) | OK |

### D — Denial of Service

| Threat | Mitigation | Status |
|--------|------------|--------|
| Login flood | StrictLimiter 10 req/min | OK |
| API flood | 600 req/min per-user | OK |
| Large request body | MaxBytesReader 1MB | OK |
| DB unbounded queries | LIMIT on all 24/24 queries | OK |
| Findings dump | max=500 enforced | OK |
| Scanner abuse | StrictLimiter 5/min on batch | OK |

### E — Elevation of Privilege

| Threat | Mitigation | Status |
|--------|------------|--------|
| Horizontal privilege | tenant_id filter on all queries | OK |
| Vertical privilege | RequireRole("admin") middleware | OK |
| Container escape | nonroot UID 65534, scratch image | OK |
| Dependency CVEs | govulncheck CI, crypto v0.50 | OK |
| gRPC auth bypass | Upgraded v1.73-dev to v1.80 (CVSS 9.1) | OK |

## Remaining Risks

| Risk | Severity | Notes |
|------|----------|-------|
| No WAF in front of gateway | HIGH | CloudFlare/nginx recommended |
| JWT secret rotation runbook | HIGH | Document rotation process |
| Secrets in env vars, not Vault | MEDIUM | Vault migration planned |
| MFA not enforced for admins | MEDIUM | Policy config needed |
| DAST coverage tuning | LOW | Nuclei in CI, needs templates |

## Security Contacts

- Security issues: soc@agency.gov
- CVE disclosure: See SECURITY.md
