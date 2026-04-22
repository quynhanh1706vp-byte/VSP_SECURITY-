# IaC Security Risk Acceptance Register

Documents intentional deviations from kics/checkov best practices, with
justification and compensating controls. Reviewed quarterly by Security Team.

## RA-001: Docker socket mount in scanner container (HIGH)

**File:** `docker/compose.prod.yml:70`

```yaml
- /var/run/docker.sock:/var/run/docker.sock:ro
```

**Risk:** Scanner container can enumerate host containers, inspect images,
read container logs via Docker API. Read-only (`:ro`) limits mutation but
information disclosure remains possible.

**Why accepted:**
- Scanner needs to build images during SCA + container scan workflows
- Full rootless Docker requires infrastructure redesign (planned Q3 2026)
- Scanner container runs on dedicated scan node, isolated from user traffic

**Compensating controls:**
1. Read-only mount (`:ro`)
2. Scanner container runs as non-root user (UID 10001)
3. Separate network namespace — no ingress from user-facing gateway
4. All scanner API calls audited via Docker audit log to SIEM
5. Scanner node subject to stricter access control (MFA required)

**Migration plan:**
- Q3 2026: Evaluate Podman + socket activation
- Q4 2026: Move to rootless Docker with buildkit socket only

**Review date:** 2026-04-22 | **Next review:** 2026-07-22 | **Owner:** SRE

---

## RA-002: OpenAPI `security: []` on public endpoints (HIGH)

**File:** `api/openapi.yaml:260, 280`

**Affected endpoints:**
- `GET /api/p4/health` (line 260) — public health check for load balancers
- `POST /api/v1/auth/login` (line 280) — pre-auth by definition

**Why accepted:**
- Health endpoint MUST be reachable without auth for K8s livenessProbe
- Login endpoint cannot require auth (chicken-and-egg)

**Compensating controls:**
- Rate limited: 10 req/min per IP on login
- Account lockout: 5 failed attempts → 15 min lock
- Health endpoint returns minimal info (no version/internal errors)
- All other endpoints default to `BearerAuth: []` via global security

**Review date:** 2026-04-22 | **Next review:** annually | **Owner:** Platform
