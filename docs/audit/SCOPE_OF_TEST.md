# VSP — Scope of Security Test

**Companion to:** `3PAO_STATEMENT_OF_WORK.md`
**Audience:** Selected 3PAO assessor
**Effective:** at engagement kickoff

This document tells the assessor what to test, what to leave alone,
and how to reach VSP staff during the engagement.

---

## 1. Targets

### Web / API surface

| Target | URL pattern | Notes |
|--------|-------------|-------|
| Production gateway | `https://app.vsp.vn/api/v1/*` | Read-only without admin token |
| Staging gateway | `https://staging.vsp.vn/api/v1/*` | Full auth surface; **preferred test target** |
| Anonymous endpoints | `/api/v1/status`, `/api/v1/security/disclose`, `/.well-known/*` | DoS-test allowed in staging only |
| Admin endpoints | All `r.With(requireRole("admin"))` paths | Admin tokens issued to assessor for the engagement |

### Container images

| Image | Where | Verify with |
|-------|-------|-------------|
| `ghcr.io/vsp/gateway:1.4.0` | Public | `cosign verify --key vsp-public.pem` |
| `ghcr.io/vsp/cosign-api:1.4.0` | Public | same |
| `ghcr.io/vsp/dast-api:1.4.0` | Public | same |
| Other 14 microservices | Public | same |

### Source code

GitHub repository: `github.com/vsp-platform/vsp` (commit `45c7337` and
later). Clone access for assessor: read-only deploy key.

### Infrastructure

Kubernetes manifests in `deploy/helm/`. Assessor receives kubeconfig
to a dedicated assessment namespace seeded with synthetic data.

---

## 2. Authentication

| Credential | Issued at | Scope | Rotation |
|------------|-----------|-------|----------|
| Assessor JWT (analyst role) | kickoff | read all panels in staging | weekly |
| Assessor JWT (admin role) | week 2 | full admin surface in staging | weekly |
| Assessor API key | kickoff | identical scope to JWT | weekly |
| Assessor PostgreSQL read-only role | week 2 | non-customer-data tables | engagement-end |
| Assessor SSH key | kickoff | jump host only | engagement-end |

All credentials are revoked automatically at engagement end via the
`/api/v1/auth/blacklist` admin endpoint.

---

## 3. In-scope tests (encouraged)

- All OWASP API Security Top 10 against `/api/v1/*`
- OWASP Top 10 against `/`, `/trust`, `/static/*`
- Authentication bypass attempts (JWT + cookie + API key paths)
- Authorisation bypass (RBAC, RLS, tenant isolation)
- IDOR enumeration on resource paths (`{id}` parameters)
- SSRF via webhook URLs, integration configs
- Path traversal in evidence file uploads
- File upload abuse (zip bombs, polyglot files)
- Rate limit + lockout bypass
- Constant-time comparison verification (login timing)
- WebAuthn flow against `/api/v1/auth/webauthn/*`
- DSAR + erasure flow correctness
- Audit chain tampering attempts
- KPI sanity bypass attempts (try to make /sanity return 200 with bad invariants)
- Container image content (cosign verify, SBOM check, distroless verify)
- Helm chart misconfiguration (e.g. running with `--set podSecurityContext.runAsNonRoot=false` should be flagged)

---

## 4. Out-of-scope tests (do not run without prior approval)

- Production gateway (`app.vsp.vn`) DoS / load tests
- Customer-tenanted data exfiltration
- Live email / SMS / phone phishing of VSP staff
- Physical intrusion attempts
- Tests that require law-enforcement coordination
- Tests against integrations (Stripe, VirusTotal, Slack) that
  would generate spam / abuse on those services
- Brute force against any account using a real human's email

If the assessor identifies a risk that requires testing one of the
above, scope it as a separate written request to the engagement
sponsor.

---

## 5. Test environment

The assessor will be provided:

1. **Staging URL**: `https://staging.vsp.vn` (kubeconfig + DNS)
2. **Synthetic tenant**: `tenant-3pao-2026` with seeded but fictitious data
3. **Test scan corpus**: ~50 sample repositories pre-imported
4. **Vault dev mode**: cluster-internal Vault with rotation worker active
5. **Assessor logging**: every assessor request tagged via `X-3PAO-Engagement-Id` header

Synthetic data is regenerated weekly. Assessor must not introduce real
secrets / production data.

---

## 6. Reporting cadence

| Frequency | Channel |
|-----------|---------|
| Daily standups (15 min) | Slack DM or Google Meet |
| Weekly status (PDF) | Friday EOD |
| Critical-finding alert | within 4 hours of discovery, encrypted email + verbal call |
| High-finding alert | within 1 business day |
| Final SAR | per SOW §3 |

For Critical findings the assessor MUST contact `security@vsp.vn` AND
the engagement sponsor before public discussion or further testing
that could expand the impact.

---

## 7. Liaison contacts

| Role | Name | Email | Phone |
|------|------|-------|-------|
| Engagement sponsor (CISO) | _to be filled_ | _to be filled_ | _to be filled_ |
| Engineering POC | _to be filled_ | engineering@vsp.vn | _to be filled_ |
| Compliance POC | _to be filled_ | compliance@vsp.vn | _to be filled_ |
| Out-of-hours emergency | on-call rotation | security@vsp.vn | _PagerDuty_ |

---

## 8. Acceptance of scope

The 3PAO acknowledges by countersigning that:

- It will not test out-of-scope targets in §4 without written approval.
- It will report Critical findings within 4 hours of discovery.
- All access credentials will be returned / destroyed at engagement end.
- All assessor deliverables will exclude customer data.

| | |
|---|---|
| 3PAO signatory: | _____________________ |
| Date: | _____________________ |
| VSP signatory: | _____________________ |
| Date: | _____________________ |
