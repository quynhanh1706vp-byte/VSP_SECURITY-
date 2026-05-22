// Package handler — System Security Plan (SSP) auto-generator.
//
// FedRAMP requires every cloud system to publish a SSP. The official
// template is 100+ pages of administrative content interleaved with
// the actual control responses. This generator fills in the
// administrative content from VSP's tenant config + control responses
// from the same evidence the OSCAL endpoints already serve.
//
// Output format: markdown (renderable to .docx via pandoc) or JSON
// for OSCAL-aware tooling (the existing /api/p4/oscal/ssp endpoint
// serves OSCAL JSON). This endpoint complements that with a
// human-readable rendering.
//
// GET /api/v1/compliance/ssp.md   — markdown
package handler

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type SSPGenerator struct {
	DB *store.DB
}

func NewSSPGenerator(db *store.DB) *SSPGenerator { return &SSPGenerator{DB: db} }

// Markdown emits a FedRAMP-shaped SSP populated with VSP-specific
// content. Admin-only — SSP is sensitive enough that we don't want
// it indexable.
func (g *SSPGenerator) Markdown(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden — admin role required", http.StatusForbidden)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), g.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	var tenantName string
	_ = g.DB.Pool().QueryRow(r.Context(),
		`SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&tenantName)
	if tenantName == "" {
		tenantName = "VSP Tenant"
	}

	now := time.Now().UTC()
	var b bytes.Buffer
	g.writeFront(&b, tenantName, now)
	g.writeSystemDescription(&b, tenantName)
	g.writeBoundary(&b)
	g.writeControlNarrative(&b, "AC", "Access Control")
	g.writeControlNarrative(&b, "AU", "Audit and Accountability")
	g.writeControlNarrative(&b, "IA", "Identification and Authentication")
	g.writeControlNarrative(&b, "SC", "System and Communications Protection")
	g.writeControlNarrative(&b, "SI", "System and Information Integrity")
	g.writeControlNarrative(&b, "CM", "Configuration Management")
	g.writeControlNarrative(&b, "IR", "Incident Response")
	g.writeControlNarrative(&b, "RA", "Risk Assessment")
	g.writeControlNarrative(&b, "SA", "System and Services Acquisition")
	g.writeAttestation(&b, tenantName, claims.UserID, now)

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="VSP-SSP-%s.md"`, now.Format("2006-01-02")))
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write(b.Bytes())
	logAudit(r, g.DB, "SSP_EXPORTED", "ssp/"+tenantID)
}

// ── front matter & boilerplate ─────────────────────────────────────────────

func (g *SSPGenerator) writeFront(b *bytes.Buffer, tenant string, now time.Time) {
	fmt.Fprintf(b, `---
title: System Security Plan (SSP)
subtitle: %s
author: VSP Platform — Compliance
date: %s
---

# 1. System Identification

| Field | Value |
|-------|-------|
| System name | VSP — Vietnam Security Platform |
| Tenant | %s |
| Version | 1.4.0 |
| Categorization | FedRAMP Moderate (FIPS PUB 199) |
| Authorization boundary | Defined in §3 |
| System owner | VSP Platform Engineering |
| Authorizing official | _to be designated by tenant_ |
| Date prepared | %s |
| Document classification | UNCLASSIFIED // FOR OFFICIAL USE ONLY |

# 2. Information System Description

VSP is a multi-tenant DevSecOps platform providing application
security testing, supply chain integrity verification, continuous
compliance monitoring, and incident response across 26 integrated
scanner tools.

## 2.1 Purpose

The system supports software development lifecycle security across
SAST, SCA, IaC, DAST, secrets, network, supply chain, and runtime
analysis dimensions, producing unified findings, OSCAL-formatted
compliance evidence, and SLSA-attestation artefacts.

## 2.2 Information types

Per NIST SP 800-60, the system processes:

- **Software configuration data** (low impact)
- **Vulnerability findings + scan results** (moderate impact —
  potential disclosure of customer software weaknesses)
- **Audit and accountability records** (moderate impact)
- **Authentication credentials** (high impact — TOTP secrets,
  WebAuthn credentials, JWT signing material)
- **Personally identifiable information** (moderate impact —
  user emails, IP addresses subject to PDPA Decree 13/2023)

The system does NOT process:

- Cardholder primary account numbers (PANs)
- Protected health information (PHI)
- Classified national-security information

## 2.3 Operational status

| Lifecycle phase | Status |
|------------------|--------|
| Initial Development | Complete |
| Deployment | Production |
| Operations & Maintenance | Active |

`,
		tenant, now.Format("2 January 2006"), tenant, now.Format("2 January 2006"))
}

func (g *SSPGenerator) writeSystemDescription(b *bytes.Buffer, tenant string) {
	b.WriteString(`# 3. System Architecture and Boundary

## 3.1 Hardware / Network

The system deploys as 17 microservice binaries (one Helm chart)
fronted by an HTTP API gateway. Cluster requirements:

- Kubernetes 1.27+
- PostgreSQL 14+ (managed or self-hosted)
- Redis 6+ (managed or self-hosted)

See ` + "`docs/ARCHITECTURE.md`" + ` for the diagram.

## 3.2 Authorization boundary

Inside boundary:

- VSP gateway, scheduler, scanner, cosign-api, dast-api, email-api,
  trivy-api, sw-agent, sw-inventory, soc-shell, vsp-cli, vsp-agent
- Database (Postgres) and queue (Redis) owned by tenant
- Helm chart and configuration

Outside boundary:

- Customer source repositories (mounted read-only at scan time)
- Third-party scan tools (e.g. trivy CLI, semgrep CLI)
- Stripe (billing)
- VirusTotal / threat intel feeds
- Notification recipients (Slack, Teams, PagerDuty)
- 3PAO assessment infrastructure (during engagement)

## 3.3 Communications and Encryption

- All ingress: TLS 1.3 minimum, HSTS enforced
- Database connection: TLS verify-full
- Outbound webhooks: TLS 1.3 + SPKI cert pinning + HMAC body sign
- Internal service-to-service: TLS via service mesh (customer choice)
- Audit log: SHA-256 chained

`)
}

func (g *SSPGenerator) writeBoundary(b *bytes.Buffer) {
	b.WriteString(`## 3.4 Data flows

| Flow | Source | Destination | Protocol | Encryption |
|------|--------|-------------|----------|------------|
| User authentication | Browser | Gateway | HTTPS | TLS 1.3 + WebAuthn |
| Scan job dispatch | Gateway | Scanner | gRPC / HTTP | TLS 1.3 |
| Scan results | Scanner | Postgres | TCP | TLS verify-full |
| Notification fan-out | Gateway | External webhook | HTTPS | TLS 1.3 + SPKI pin + HMAC |
| Audit chain query | Auditor | Gateway | HTTPS | TLS 1.3 + RBAC |
| Compliance evidence | Tenant admin | Gateway | HTTPS | TLS 1.3 + admin role |

`)
}

// ── control narratives ─────────────────────────────────────────────────────

// Control narrative for a NIST 800-53 family. Mostly canned text +
// VSP evidence references for the specific implementation.
func (g *SSPGenerator) writeControlNarrative(b *bytes.Buffer, family, name string) {
	fmt.Fprintf(b, "# 4. Control Family — %s — %s\n\n", family, name)
	switch family {
	case "AC":
		b.WriteString(controlACNarrative)
	case "AU":
		b.WriteString(controlAUNarrative)
	case "IA":
		b.WriteString(controlIANarrative)
	case "SC":
		b.WriteString(controlSCNarrative)
	case "SI":
		b.WriteString(controlSINarrative)
	case "CM":
		b.WriteString(controlCMNarrative)
	case "IR":
		b.WriteString(controlIRNarrative)
	case "RA":
		b.WriteString(controlRANarrative)
	case "SA":
		b.WriteString(controlSANarrative)
	}
	b.WriteString("\n")
}

func (g *SSPGenerator) writeAttestation(b *bytes.Buffer, tenant, signerHint string, now time.Time) {
	b.WriteString("# 5. Plan Acceptance and Attestation\n\n")
	b.WriteString("## 5.1 Continuous Monitoring Strategy\n\n")
	b.WriteString(strings.TrimSpace(continuousMonitoringNarrative))
	b.WriteString("\n\n")
	b.WriteString("## 5.2 Plan of Action and Milestones (POA&M)\n\n")
	b.WriteString("Open POA&M items are queryable via `GET /api/p4/oscal/poam`. ")
	b.WriteString("Two business-side items remain open as of this SSP version:\n\n")
	b.WriteString("1. **3PAO engagement** (RISK_REGISTER R-021) — mitigated by tabletop registry + 26-tool scan coverage; closure requires external assessor.\n")
	b.WriteString("2. **Bug bounty operational** (RISK_REGISTER R-022) — code intake ready, business contract pending.\n\n")
	b.WriteString("## 5.3 Signature\n\n")
	b.WriteString("This SSP is hereby submitted for the system identified in §1.\n\n")
	fmt.Fprintf(b, "| | |\n|---|---|\n| System owner: | %s |\n| Authorising official: | _signature pending_ |\n| Date: | %s |\n\n",
		tenant, now.Format("2 January 2006"))
	fmt.Fprintf(b, "Generated by VSP SSP Generator v1.0 on behalf of user %s.\n", signerHint)
}

// ── canned narratives (single source of truth, edited via PR) ─────────────

const controlACNarrative = `**AC-2 Account Management.** User account lifecycle is managed via
` + "`internal/api/handler/users.go`" + `; create / disable / role
changes are RBAC-gated and audit-logged. Inactive accounts are
flagged after 90 days of inactivity.

**AC-3 Access Enforcement.** Database row-level security enforces
tenant isolation as defence-in-depth (` + "`migrations/037_row_level_security.sql`" + `).
Application-layer filters (` + "`WHERE tenant_id`" + `) sit on top.

**AC-7 Unsuccessful Logon Attempts.** 5 failed attempts within 15
minutes locks the account; 20 IP-level fails in 10 min triggers a
sliding-window IP lockout (` + "`internal/auth/lockout.go`" + `).

**AC-12 Session Termination.** UEBA anomaly detector revokes all
tokens on impossible-travel or rapid IP rotation
(` + "`internal/auth/anomaly_revoke.go`" + `).

**AC-22 Publicly Accessible Content.** ` + "`/trust/`" + ` Trust Center
+ ` + "`/.well-known/security.txt`" + ` are anonymous-readable; everything
else requires authentication.

`

const controlAUNarrative = `**AU-2 Audit Events.** Every state-changing API call writes to
` + "`audit_log`" + ` with action / resource / user_id / IP / timestamp.

**AU-3 Content of Audit Records.** ` + "`audit_log`" + ` schema captures
seq / tenant_id / user_id / action / resource / IP / payload (JSONB) /
hash / prev_hash / created_at.

**AU-9 Protection of Audit Information.** Each row's hash is SHA-256
of (prev_hash || action || resource || created_at). Tampering breaks
the chain; ` + "`POST /api/v1/audit/verify`" + ` walks the chain and
` + "`POST /api/v1/audit/repair`" + ` rebuilds with a confirmation token.

**AU-11 Audit Record Retention.** Retention is per-tenant policy;
default is 7 years aligned with FedRAMP requirement 3.5.x.

`

const controlIANarrative = `**IA-2 Identification and Authentication (Organizational Users).**
WebAuthn / FIDO2 (` + "`internal/auth/webauthn.go`" + ` + go-webauthn
library) + TOTP MFA + JWT with HMAC-SHA256.

**IA-2(1) MFA for Privileged Accounts.** Admin role MUST present
both factor types; enforced in ` + "`internal/api/middleware/`" + ` admin
gating.

**IA-5 Authenticator Management.** Bcrypt cost 12 + HIBP breach check
on password create/reset (` + "`internal/auth/hibp.go`" + `).

**IA-12 Session Termination.** UEBA-driven auto session revoke; logout
endpoint blacklists JWT in Redis.

`

const controlSCNarrative = `**SC-7 Boundary Protection.** NetworkPolicy in
` + "`deploy/helm/templates/networkpolicy.yaml`" + ` allows DNS-only
egress by default; operator adds explicit egress for DB/Redis/Vault.

**SC-8 Transmission Confidentiality and Integrity.** TLS 1.3 minimum
on ingress; SPKI cert pinning on outbound webhooks
(` + "`internal/notify/pin.go`" + `); HMAC-SHA256 body signing.

**SC-12 Cryptographic Key Establishment and Management.** Vault
provider abstraction (` + "`internal/secrets/`" + `) with auto-rotation;
ECDSA P-256 for SLSA / DSSE attestation signing.

**SC-13 Cryptographic Protection.** Bcrypt cost 12, ECDSA P-256, SHA-256,
TLS 1.3, HMAC-SHA256.

**SC-28 Protection of Information at Rest.** PostgreSQL bytea blobs for
sensitive data; row-level security on 9 critical tables.

`

const controlSINarrative = `**SI-2 Flaw Remediation.** AutoPR / AutoFix workflow
(` + "`internal/autopr/` + `internal/autofix/`" + `) generates fix PRs with
SLA-based auto-merge.

**SI-3 Malicious Code Protection.** trivy + grype + cosign verify in
the supply chain pipeline; secretcheck validates exposed credentials
via live API calls.

**SI-4 System Monitoring.** ConMon (` + "`internal/conmon/`" + `) +
UEBA + KPI watchdog (` + "`internal/api/handler/kpi_watchdog.go`" + `)
re-runs sanity invariants every 5 min.

**SI-7 Software, Firmware, and Information Integrity.** SLSA L3
DSSE attestations per scan run; Rekor public publishing available.

`

const controlCMNarrative = `**CM-2 Baseline Configuration.** Helm chart at ` + "`deploy/helm/`" + `
defines the baseline; values.yaml restrictive defaults.

**CM-3 Configuration Change Control.** GitHub branch protection +
CODEOWNERS for 22 paths; change requires review.

**CM-6 Configuration Settings.** ` + "`deploy/helm/values.yaml`" + `
sets non-root user, read-only filesystem, RuntimeDefault seccomp,
drop ALL caps, automountServiceAccountToken false.

**CM-7 Least Functionality.** Default container has only the gateway
binary + tini init; no shell, package manager, or interactive tooling.

**CM-8 System Component Inventory.** SBOM via syft published at
` + "`/sbom.cyclonedx.json`" + `; compositional analysis via
osv-scanner + retire-js + grype.

`

const controlIRNarrative = `**IR-1 Incident Response Policy and Procedures.** ` + "`docs/RUNBOOK.md`" + `
+ ` + "`docs/audit/AUDIT_ENGAGEMENT_GUIDE.md`" + `.

**IR-3 Incident Response Testing.** Tabletop exercise registry
(` + "`migrations/042_tabletop_exercises.sql`" + `) tracks scenario
cadence; cadence dashboard flags overdue exercises.

**IR-4 Incident Handling.** NIST 800-61r3 lifecycle implemented in
` + "`migrations/017_incident_response_circia.sql`" + ` with phases
preparation → detection_analysis → containment → eradication →
recovery → post_incident.

**IR-6 Incident Reporting.** CIRCIA 72h workflow generates
` + "`circia_reports`" + ` rows for substantial incidents.

**IR-8 Incident Response Plan.** Documented; tested via
quarterly tabletop exercises per ` + "`docs/audit/RISK_REGISTER.md`" + `.

`

const controlRANarrative = `**RA-3 Risk Assessment.** Living risk register at
` + "`docs/audit/RISK_REGISTER.md`" + `; reviewed quarterly with
emergency triggers on incident or external finding.

**RA-5 Vulnerability Scanning.** 26 scanner integrations across SAST
/ SCA / IaC / DAST / secrets / network / supply chain / fuzz; CVE
findings enriched with EPSS + KEV.

**RA-7 Risk Response.** AutoPR generates remediation PRs; POA&M
tracks open critical items with deadline-based escalation.

`

const controlSANarrative = `**SA-3 System Development Life Cycle.** NIST SSDF (SP 800-218)
mapped; CISA SSDF Common Form 2024 auto-generated from live
evidence.

**SA-8 Security and Privacy Engineering Principles.** Reviewed in
` + "`docs/SECURITY_DECISIONS.md`" + `; secure-by-default Helm chart;
fail-closed where ambiguous.

**SA-10 Developer Configuration Management.** branch protection +
signed commits roadmap + 22-path CODEOWNERS.

**SA-11 Developer Security Testing and Evaluation.** golangci-lint
with gosec / nilerr / sqlclosecheck enabled; tests/load/k6 SLO + chaos.

**SA-15 Development Process, Standards, and Tools.** CI runs all 26
scanners against the platform's own code; SLSA L3 attestations
on every release.

**SA-22 Unsupported System Components.** ` + "`go.mod`" + ` pinned;
dependabot auto-PRs reviewed; ` + "`govulncheck`" + ` flags retired Go
versions.

`

const continuousMonitoringNarrative = `Continuous monitoring is implemented across three layers:

1. **Configuration drift** — ConMon scheduler runs nightly comparison
   between the deployed Helm chart values and the declared baseline.
   Drift events are logged in ` + "`conmon_deviations`" + ` and require
   acknowledgement within 72 hours (cATO criterion).

2. **Vulnerability and integrity** — 26 scanners run on a per-tenant
   schedule; KPI watchdog asserts the scoring math every 5 minutes
   and writes ` + "`KPI_SANITY_FAILED`" + ` audit rows on regression.

3. **Compliance evidence** — Quarterly improvement metrics
   (` + "`/api/v1/improvement/quarters`" + `) auto-aggregate DORA + MTTR
   + audit chain integrity + disclosure SLA hits across 4 quarters.

The audit evidence bundle (` + "`/api/v1/audit/bundle`" + `) packages
all of the above into a SHA-256-pinned ZIP suitable for 3PAO review
without further operator effort.`
