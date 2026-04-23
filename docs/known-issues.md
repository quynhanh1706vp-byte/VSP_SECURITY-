# VSP — Known Security Issues

**Purpose:** Track findings that are known, accepted, or deferred to a
scheduled sprint. Researchers reporting vulnerabilities should check this
list first (per `SECURITY.md` § Out of scope).

**Label convention:** GitHub issues tracking these items use the
`security-known` label.

---

## Active Known Issues

### #62 — CodeQL pre-existing alerts (15 findings)

**Status:** Deferred to Sprint 2 triage
**Severity:** Mixed (to be classified during triage)
**Introduced by:** Pre-existing (not from Sprint 0 changes)
**Compensating controls:** CSP, postMessage origin check (VSP-SEC-001),
CI guards

**Breakdown:**

| Category | Count |
|----------|-------|
| XSS (DOM-based) | 9 |
| CSRF | 2 |
| Unreachable code | 2 |
| XSS via exception message | 2 |

**See:** `docs/security/codeql-triage.md` for triage plan and export
instructions.

---

### SD-0045 — Tenant isolation: 10 internal queries without `tenant_id`

**Status:** Documented, accepted
**Severity:** LOW (internal-only code paths)
**Compensating controls:** Paths are service-to-service, not exposed
via API; documented in `docs/COMPLIANCE_MATRIX.md` § AC-4.

**Coverage:** 82/92 queries enforce `tenant_id`. The remaining 10 are
called only by scheduled jobs and admin CLI tools running inside the
tenant-scoped process.

---

### SEC-009 — SSE/WebSocket token via query param

**Status:** Migration in progress (Sprint 4 frontend work)
**Severity:** MEDIUM
**Current state:** `internal/api/handler/ws.go:42` accepts `?token=`
query param. EventSource API cannot set headers, so cookie-based auth
requires frontend refactor.
**Compensating controls:** HTTPS-only, token has short TTL,
middleware blocks `?token=` on non-SSE endpoints.

---

## How to Report a New Issue

If you found something **not** on this list, follow the disclosure
process in `SECURITY.md`. Before filing, please:

1. Check this file for an existing entry.
2. Search GitHub issues with the `security-known` label.
3. Include a working PoC — theoretical issues are out of scope.

---

## Last Updated

2026-04-23 (Sprint 0 Task 2.2a)

See also: `THREAT_MODEL.md` § Known Limitations for the same list in
threat-model context.
