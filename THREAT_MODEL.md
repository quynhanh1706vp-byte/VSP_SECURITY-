# VSP Security Platform — Threat Model (STRIDE)

**Version:** 1.2 | **Date:** 2026-04-23 | **Method:** STRIDE

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
| Token in SSE/WS URL | Cookie migration in progress (SEC-009); `ws.go:42` still accepts `?token=` query | IN_PROGRESS |
| Brute force login | 10 req/min + lockout after 5 fails | OK |
| Session fixation | New JWT issued on every login | OK |
| CAC/PIV bypass | OIDC validation, no Referer bypass | OK |
| postMessage origin bypass | `VSPOrigin.check()` on 17 panels + 5 CI guards (VSP-SEC-001, PR #61) | OK |
| JWT key compromise | Dual-secret rotation (`internal/auth/rotation.go`, PR #63); 24h transition window | OK |

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
| Token in SSE URL | Cookie migration pending (SEC-009); middleware blocks non-SSE paths only | IN_PROGRESS |
| Secrets in repo | pre-commit gitleaks + CI gitleaks | OK |
| User enumeration | Generic "invalid credentials" message | OK |
| Tenant data leak | tenant_id on 82/92 queries (10 internal-only, SD-0045) | OK |
| Anthropic API open relay | Frontend proxy removed (dead code purge, PR #61); CSP blocks `api.anthropic.com` | OK |

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
| MFA enforced for admins | Login gate at `handler/auth.go:109` rejects admin login when MFA incomplete; active when `server.env=production\|staging` (dev allows warn+continue) | OK (prod/staging) |

## Remaining Risks

| Risk | Severity | Notes |
|------|----------|-------|
| No WAF in front of gateway | HIGH | CloudFlare/nginx recommended |
| Secrets in env vars, not Vault | MEDIUM | Vault migration planned |
| DAST coverage tuning | LOW | Nuclei in CI, needs templates |

## Known Limitations

Tracked findings from CodeQL / security tooling, deferred to a scheduled sprint
rather than blocking current release. These are **known and accepted**, not unmanaged.

| ID | Category | Count | Tracked In | Scheduled |
|----|----------|-------|------------|-----------|
| #62 | CodeQL XSS | 9 | GitHub issue #62 | Sprint 2 triage |
| #62 | CodeQL CSRF | 2 | GitHub issue #62 | Sprint 2 triage |
| #62 | CodeQL unreachable | 2 | GitHub issue #62 | Sprint 2 triage |
| #62 | CodeQL XSS-via-exception | 2 | GitHub issue #62 | Sprint 2 triage |
| SD-0045 | Tenant isolation gaps | 10 queries | `docs/COMPLIANCE_MATRIX.md` | Internal-only paths; documented |
| SEC-009 | SSE cookie migration | 1 handler | `ws.go:42` | Sprint 4 frontend work |

**Status:** These items are pre-existing (not introduced by Sprint 0) and have
compensating controls (CSP, origin checks, CI guards) preventing exploitation
in the interim.

## Security Contacts

- Security issues: soc@agency.gov
- CVE disclosure: See SECURITY.md

---

## Verification Log

- **2026-04-20**: Claims cross-checked against `internal/api/middleware/*.go`,
  `internal/store/*.go`, and `cmd/gateway/main.go`. Tenant isolation count
  updated from 59/59 to 82/92 (actual query count). SSE token claim marked
  IN_PROGRESS (frontend migration SEC-009 pending). MFA enforcement marked
  IN_PROGRESS (TOTP available, policy enforcement Sprint 4 PR #B).

- **2026-04-23**: Post-Sprint 0 update (v1.1). Added STRIDE rows for
  VSP-SEC-001 (postMessage origin check, PR #61) and JWT dual-secret rotation
  (PR #63). SSE token rows re-synced to IN_PROGRESS to match `ws.go:42`
  implementation. MFA row moved from Remaining Risks to § E (TOTP code exists,
  policy enforcement pending). Known Limitations section added linking issue #62
  (15 CodeQL findings, Sprint 2 triage scope).

- **2026-04-23 (afternoon, v1.2)**: MFA row status IN_PROGRESS → OK
  (prod/staging). Root-caused and fixed admin lockout race in `SetMFASecret`
  (was setting `mfa_enabled=true` before user confirmed TOTP). Added
  `ConfirmMFAEnabled` method for atomic enable+verify at `/auth/mfa/verify`.
  Migration 018 resets dirty-state rows. `SERVER_ENV` check refactored to
  use viper (consistency with `auth.mode`). See commits `de58740` (bug fix)
  and `717ccc2` (refactor).

**Next verification:** 2026-07-23 (quarterly cadence).
