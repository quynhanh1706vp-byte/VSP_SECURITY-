# VSP Security Platform — Architecture

**Version:** 1.0
**Last updated:** 2026-04-20
**Audience:** Engineers, auditors, security reviewers, new hires

This document describes VSP's architecture using the [C4 model](https://c4model.com/)
(Context → Container → Component → Code). It is the authoritative source for
system design; update it when architecture changes.

---

## 1. Context Diagram (C4 Level 1)

```
                        ┌─────────────────────┐
                        │   SOC Analyst       │
                        │   (browser)         │
                        └──────────┬──────────┘
                                   │ HTTPS
                                   ▼
  ┌─────────────┐       ┌─────────────────────┐      ┌──────────────────┐
  │ CI/CD       │──────▶│                     │─────▶│ External         │
  │ (GitHub,    │ agent │   VSP Platform      │ API  │ Services         │
  │  GitLab)    │◀──────│                     │      │ - Anthropic LLM  │
  └─────────────┘       │  - Gateway :8921    │      │ - OIDC (Okta,    │
                        │  - Scanner workers  │◀─────│   Entra, Auth0)  │
  ┌─────────────┐       │  - SIEM engine      │      │ - Stripe billing │
  │ Customer    │──────▶│  - Scheduler        │      │ - Slack webhook  │
  │ APIs        │       │                     │      │ - OSCAL registry │
  │ (webhook,   │       └──────┬──────────────┘      └──────────────────┘
  │  agent)     │              │
  └─────────────┘              │
                               ▼
                        ┌──────────────┐  ┌─────────────┐
                        │ PostgreSQL   │  │ Redis       │
                        │ (findings,   │  │ (sessions,  │
                        │  audit log,  │  │  rate limit)│
                        │  tenants)    │  │             │
                        └──────────────┘  └─────────────┘
```

### External actors

| Actor | Purpose | Authentication |
|-------|---------|----------------|
| **SOC Analyst** | Primary user — views findings, runs scans, investigates incidents | OIDC + MFA (TOTP), session cookie |
| **CI/CD systems** | Trigger scans on commit, fetch results | API key (X-API-Key header) |
| **Customer agents** | Stream telemetry, host-based scan results | mTLS or API key |
| **Admin** | Tenant management, billing, ATO compliance | OIDC + MFA (required) |

### External services

| Service | Why VSP uses it | Failure mode |
|---------|-----------------|--------------|
| Anthropic Claude API | AI analyst explanations, remediation suggestions | Graceful degradation — findings shown without AI summary |
| OIDC providers | SSO for enterprise customers | Fallback to local auth (admin-only) |
| Stripe | Metered billing for scan volume | Grace period, read-only mode on failure |
| Slack webhook | CRITICAL finding notifications | Optional, logged if fails |

---

## 2. Container Diagram (C4 Level 2)

VSP is a monorepo with 8 binaries, each deployable independently.

```
                    ┌──────────────────────────────────────┐
                    │          API Gateway :8921           │
  HTTPS     ───────▶│  cmd/gateway                         │
  (browser,         │  - HTTP routing (chi router)         │
   CLI,             │  - Middleware stack:                 │
   agent)           │    CSP, CSRF, RateLimit,             │
                    │    CookieSession, Auth               │
                    │  - Async audit goroutines            │
                    └──┬─────────┬───────────┬─────────────┘
                       │         │           │
             ┌─────────┘         │           └───────────┐
             ▼                   ▼                       ▼
   ┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
   │ Scanner      │   │ Scheduler        │   │ SOC Shell :8922  │
   │ cmd/scanner  │   │ cmd/gateway      │   │ cmd/soc-shell    │
   │              │   │ (embedded)       │   │                  │
   │ 19 tools:    │   │                  │   │ Interactive      │
   │ SAST(5):     │   │ Cron-based scans │   │ investigator     │
   │  gosec,      │   │ Next run         │   │ for SOC analysts │
   │  semgrep,    │   │ persisted in DB  │   │                  │
   │  bandit,     │   └──────────────────┘   └──────────────────┘
   │  codeql,     │
   │  hadolint    │   ┌──────────────────┐   ┌──────────────────┐
   │ SCA(3):      │   │ SIEM Engine      │   │ Agent            │
   │  trivy,      │   │ (syslog receiver)│   │ cmd/vsp-agent    │
   │  grype,      │   │ :10514 UDP       │   │                  │
   │  license     │   │ :10515 TCP       │   │ On-premise       │
   │ IaC(2):      │   │                  │   │ customer scans   │
   │  checkov,    │   │ Playbook engine  │   │                  │
   │  kics        │   │ (SOAR)           │   └──────────────────┘
   │ DAST(2):     │   │                  │
   │  nuclei,     │   │ UEBA (7 anomaly  │
   │  nikto       │   │  types)          │
   │ Secrets(2):  │   │                  │
   │  gitleaks,   │   │ Correlator +     │
   │  secretcheck │   │ Retention        │
   │ Network(3):  │   └──────────────────┘
   │  nmap,       │
   │  sslscan,    │
   │  netcap      │
   │ + license,   │
   │   runner,    │
   │   enrich     │
   └──────────────┘
                      └──────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
            ┌──────────────┐       ┌──────────────┐
            │ PostgreSQL   │       │ Redis        │
            │ 16-alpine    │       │ 7-alpine     │
            │              │       │              │
            │ Schema:      │       │ Usage:       │
            │ - findings   │       │ - Sessions   │
            │ - audit_log  │       │ - Rate limit │
            │   (hash      │       │ - Scan job   │
            │   chain)     │       │   queue      │
            │ - tenants    │       │ - Cache      │
            │ - users      │       │              │
            │ - api_keys   │       │              │
            │ - playbooks  │       │              │
            │ - p4_state   │       │              │
            └──────────────┘       └──────────────┘
```



### P4 Compliance Automation Module

Not a separate binary — P4 endpoints are registered in `cmd/gateway/main.go:357-400`.
Provides automation for NIST/FedRAMP/CMMC/CISA compliance workflows.

```
┌────────────────────────────────────────────────────────────────┐
│                  P4 Compliance Automation                      │
│                                                                 │
│   ┌─────────────────┐      ┌─────────────────┐                │
│   │ OSCAL 1.1.2     │      │ NIST RMF        │                │
│   │ /api/p4/oscal/* │      │ /api/p4/rmf/*   │                │
│   │ - Catalog       │      │ - State machine │                │
│   │ - Profile       │      │ - ATO letter    │                │
│   │ - SSP (+ext)    │      │ - ConMon        │                │
│   │ - Assessment    │      └─────────────────┘                │
│   │ - POA&M         │                                          │
│   └─────────────────┘      ┌─────────────────┐                │
│                            │ Zero Trust       │                │
│   ┌─────────────────┐      │ /api/p4/zt/*     │                │
│   │ SSDF v1.1       │      │ - Microseg       │                │
│   │ /api/p4/ssdf/*  │      │ - RASP           │                │
│   │ 19/20 practices │      │ - SBOM attest    │                │
│   └─────────────────┘      │ - API policy     │                │
│                            └─────────────────┘                │
│   ┌─────────────────┐                                          │
│   │ CISA            │      ┌─────────────────┐                │
│   │ Attestation     │      │ NIST SP 800-61r3│                │
│   │ /api/p4/        │      │ /api/p4/ir/*    │                │
│   │   attestation/* │      │ - Incidents     │                │
│   │ - ECDSA-signed  │      │ - State machine │                │
│   └─────────────────┘      │ - Forensics     │                │
│                            └─────────────────┘                │
│   ┌─────────────────┐                                          │
│   │ CIRCIA          │      ┌─────────────────┐                │
│   │ /api/p4/circia/*│      │ Governance      │                │
│   │ - 72h reporting │      │ govH.*          │                │
│   │ - Federal submit│      │ - RACI          │                │
│   └─────────────────┘      │ - Risk Register │                │
│                            │ - Roadmap       │                │
│                            │ - Traceability  │                │
│                            │ - Scorecards    │                │
│                            └─────────────────┘                │
└────────────────────────────────────────────────────────────────┘
```

Full endpoint catalog in docs/FEATURE_INVENTORY.md.

### Binary inventory

| Binary | Purpose | Runtime deps |
|--------|---------|--------------|
| `gateway` | Main HTTP API + scheduler + SIEM receiver | libpcap (CGO), PostgreSQL, Redis |
| `scanner` | Scan runner — shells out to 12+ tools | Tool binaries in PATH |
| `soc-shell` | SOC analyst CLI + TUI | PostgreSQL (read-only) |
| `vsp-agent` | On-prem agent for customer environments | Network only |
| `vsp-cli` | Admin CLI — tenant ops, token issuance | PostgreSQL |
| `seed` | Initial data seed for local dev | PostgreSQL |
| `siem-seed` | SIEM sample event generator | — |
| `migrate` | Schema migration runner (uses goose) | PostgreSQL |

### Deployment topology

**Minimum (single-tenant, small):**
- 1× gateway container (512 MB RAM)
- 1× scanner container (1 GB RAM per concurrent scan)
- 1× PostgreSQL (2 GB RAM, 20 GB disk)
- 1× Redis (256 MB RAM)

**Enterprise (multi-tenant, large):**
- 3× gateway (load-balanced, rolling update)
- 8× scanner (horizontal by scan queue depth)
- PostgreSQL primary + 2× read replicas
- Redis cluster (3 nodes)
- nginx/CloudFlare in front of gateway (TLS, WAF)

---

## 3. Component Diagram (C4 Level 3) — Gateway internals

```
cmd/gateway/main.go
    │
    ├─ Route registration (chi router)
    ├─ Middleware stack (13 layers total, order matters):
    │  1.  chimw.RequestID         — request correlation
    │  2.  chimw.RealIP             — X-Forwarded-For handling
    │  3.  vspMW.CSPNonce           — per-request 16-byte nonce
    │  4.  vspMW.CSRFProtect        — double-submit cookie
    │  5.  vspMW.RequestLogger      — structured logging
    │  6.  chimw.Recoverer          — panic recovery
    │  7.  chimw.Timeout(60s)       — global timeout
    │  8.  (custom security headers)
    │  9.  corsMiddleware           — CORS same-origin + credentials
    │  10. rl.Middleware            — global rate limiter
    │  11. authMw (per-route)       — JWT/cookie auth
    │  12. NewUserRateLimiter(600/min) — per-user rate limit
    │  13. RequireRole("admin")     — per-route RBAC
    │
    ├─ Handlers (internal/api/handler/):
    │  ├─ auth.go         — login, logout, refresh, MFA
    │  ├─ findings.go     — CRUD findings
    │  ├─ runs.go         — scan run lifecycle
    │  ├─ remediation.go  — track fixes
    │  ├─ siem_extended.go — playbook triggers
    │  ├─ netcap_handler.go — packet capture control
    │  ├─ pdf.go          — report generation
    │  └─ ...
    │
    └─ Services (internal/):
       ├─ auth/     — JWT, OIDC, MFA, API keys
       ├─ store/    — DB layer (sqlc-generated + custom)
       ├─ audit/    — hash-chain audit log
       ├─ scanner/  — tool adapters (12 tools)
       ├─ siem/     — event ingestion + playbook exec
       ├─ threatintel/ — CVE/KEV/EPSS lookups
       ├─ compliance/ — NIST 800-53, FedRAMP, CMMC mappers
       ├─ governance/ — P4 ATO state machine
       ├─ billing/  — Stripe integration
       └─ telemetry/ — OpenTelemetry traces
```

### Request flow example: `POST /api/v1/scans`

```
Browser
  │ POST /api/v1/scans { "mode": "FULL", "target": "..." }
  │ Cookie: vsp_session=<JWT>
  │ X-CSRF-Token: <token>
  ▼
Middleware stack:
  │ 1. RateLimit: check 600/min per user  ─ fail → 429
  │ 2. CSP: attach nonce to response
  │ 3. CSRF: compare header vs cookie     ─ mismatch → 403
  │ 4. CookieSession: extract JWT from cookie, validate
  │ 5. Handler auth: RequireRole("scanner_operator")  ─ fail → 403
  ▼
Handler (runs.go):
  │ 1. Parse JSON body (max 1 MB)
  │ 2. Validate tenant_id from JWT matches asset tenant
  │ 3. Insert scan run row (tenant_id enforced)
  │ 4. Enqueue to Redis job queue
  │ 5. Return 201 + scan run ID
  ▼
Response:
  │ HTTP 201 Created
  │ Set-Cookie: vsp_session=<refreshed JWT>
  │ Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'
  │ { "scan_run_id": "uuid", "status": "queued" }
```

---

## 4. Data model (key tables)

### findings
```sql
id UUID PK
tenant_id UUID NOT NULL   -- enforced on all queries (82/92 coverage)
scan_run_id UUID FK
tool TEXT                 -- gosec, trivy, nuclei, ...
rule_id TEXT              -- G101, CVE-2024-..., etc.
severity TEXT             -- CRITICAL | HIGH | MEDIUM | LOW | INFO
cvss NUMERIC(3,1)
epss NUMERIC(5,4)
message TEXT
file TEXT
line INT
status TEXT               -- open | in_progress | resolved | suppressed
created_at TIMESTAMPTZ
UNIQUE (tenant_id, rule_id, file, line)  -- dedup key
```

### audit_log (hash chain)
```sql
seq BIGSERIAL PK
ts TIMESTAMPTZ
tenant_id UUID
user_id UUID
action TEXT               -- LOGIN_OK, SCAN_TRIGGER, FINDING_RESOLVE
resource TEXT
result TEXT
ip INET
prev_hash BYTEA
hash BYTEA                -- SHA256(seq||ts||...||prev_hash)
```

Hash chain verifies integrity: `GET /api/p4/audit/verify` walks entire chain.

---

## 5. Technology choices (why these?)

| Choice | Why | Alternatives considered |
|--------|-----|-------------------------|
| **Go 1.25** | Type safety, single-binary deployment, excellent stdlib for CSP/JWT/HTTP | Rust (slower iteration), Python (weaker concurrency) |
| **chi router** | Lightweight, compatible with net/http middleware ecosystem | gin (heavier), echo (less idiomatic) |
| **PostgreSQL 16** | JSONB for findings metadata, foreign keys, strong consistency | MySQL (weaker JSON), MongoDB (no ACID for audit) |
| **Redis 7** | Low-latency session + queue + rate limiter | Memcached (no data types), NATS (overkill for our queue size) |
| **sqlc** | Type-safe queries from SQL files, no ORM magic | GORM (too much magic), raw sql (no type safety) |
| **goose** | Up/down migrations with SQL files, not Go code | golang-migrate (similar, goose has better Go embedding) |
| **CGO libpcap** | gopacket/pcap needs it for L2 capture in netcap module | eBPF (Linux-only, complex), pcap-go pure (missing features) |
| **Docker multi-stage** | Builder ~1.5 GB, runtime ~60 MB (alpine + libpcap) | Distroless (no libpcap), scratch (no ca-certificates) |

---

## 6. Deployment & operations

See [RUNBOOK.md](RUNBOOK.md) for on-call procedures.

**Production deployment flow:**
1. Commit merged to `main` → CI runs
2. CI builds Docker image, pushes to GHCR with tags: `sha-<short>`, `latest`
3. Trivy scan on image (CRITICAL+HIGH fail build)
4. SBOM generated (CycloneDX), attached to release
5. Deploy staging via SSH + `docker compose up -d`
6. Nuclei DAST runs on staging
7. Manual promote to prod (no auto-deploy to prod by policy)

---

## 7. Change log

- **2026-04-20 v1.0** — Initial C4 documentation.
- **2026-04-20 v1.1** — Scanner count corrected (12 → 19), P4 compliance
  automation module added, middleware stack detail expanded (7 → 13 layers).
  Source: docs/FEATURE_INVENTORY.md full code audit.

**Next review:** 2026-07-20 (quarterly cadence).

