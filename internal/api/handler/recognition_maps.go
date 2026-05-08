// Package handler — SOC 2 Type I + ISO 27001:2022 control mappings.
//
// Both endpoints serve the same purpose as nist_csf.go: produce a
// standards-aligned readiness profile with VSP evidence pointers, so
// a CISO has a defensible artefact to bring to a Type I audit kickoff
// or an ISO 27001 Stage 1 review without rebuilding the mapping each
// time.
//
// SOC 2 — AICPA Trust Services Criteria 2017 (rev. 2022). Type I is
// readiness/design (where we are); Type II requires 3-6 months of
// operating effectiveness evidence (out of scope until customers
// demand it).
//
// ISO 27001:2022 — Annex A reduced to 93 controls across 4 themes
// (Organisational, People, Physical, Technological). VSP covers the
// Technological controls fully + Organisational mostly; Physical and
// People depend on the deploying tenant, so we mark "shared" rather
// than claim coverage.
//
// Endpoints:
//   GET /api/v1/recognition/soc2-readiness
//   GET /api/v1/recognition/iso27001-mapping
package handler

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Recognition struct {
	DB *store.DB
}

func NewRecognition(db *store.DB) *Recognition { return &Recognition{DB: db} }

// ── SOC 2 ──────────────────────────────────────────────────────────────────

type soc2Criterion struct {
	ID       string   `json:"id"`        // e.g. "CC6.1"
	Category string   `json:"category"`  // CC | A | C | PI | P
	Name     string   `json:"name"`
	Status   string   `json:"status"`    // implemented | partial | shared
	Evidence []string `json:"evidence"`
}

func (h *Recognition) SOC2Readiness(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.FromContext(r.Context()); !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	criteria := []soc2Criterion{
		// ── Common Criteria (Security) ───────────────────────────────
		{ID: "CC1.1", Category: "CC", Name: "COSO Principle 1 — demonstrates commitment to integrity and ethical values",
			Status: "implemented", Evidence: []string{"docs/security/VULNERABILITY_DISCLOSURE_POLICY.md"}},
		{ID: "CC2.1", Category: "CC", Name: "COSO Principle 13 — uses relevant information",
			Status: "implemented", Evidence: []string{"GET /api/v1/improvement/quarters"}},
		{ID: "CC3.1", Category: "CC", Name: "COSO Principle 6 — risk identification and assessment",
			Status: "implemented", Evidence: []string{"26 scanner integrations + EPSS/KEV enrichment"}},
		{ID: "CC4.1", Category: "CC", Name: "COSO Principle 16 — monitoring activities",
			Status: "implemented", Evidence: []string{"GET /api/v1/conmon/score + KPI watchdog"}},
		{ID: "CC5.1", Category: "CC", Name: "COSO Principle 10 — control activities",
			Status: "implemented", Evidence: []string{"GET /api/v1/kpi/sanity HTTP 409 release blocker"}},
		{ID: "CC6.1", Category: "CC", Name: "Logical access — restrict access to authorised users",
			Status: "implemented", Evidence: []string{"WebAuthn + TOTP + RBAC + Postgres RLS"}},
		{ID: "CC6.2", Category: "CC", Name: "Logical access — register and authorise new users",
			Status: "implemented", Evidence: []string{"internal/api/handler/users.go + admin gating"}},
		{ID: "CC6.3", Category: "CC", Name: "Logical access — modification/removal",
			Status: "implemented", Evidence: []string{"DSR erasure + admin user deactivation"}},
		{ID: "CC6.6", Category: "CC", Name: "Logical access — restrict transmission, movement, removal",
			Status: "implemented", Evidence: []string{"TLS 1.3 + cert pinning + signed webhooks + data residency"}},
		{ID: "CC6.7", Category: "CC", Name: "Logical access — encryption-at-rest",
			Status: "partial", Evidence: []string{"Vault secrets ✓; Postgres TDE deployment-dependent"}},
		{ID: "CC6.8", Category: "CC", Name: "Prevent unauthorized software introduction",
			Status: "implemented", Evidence: []string{"cosign signed images + SLSA L3 provenance"}},
		{ID: "CC7.1", Category: "CC", Name: "System operations — vulnerability monitoring",
			Status: "implemented", Evidence: []string{"ConMon + 26 scanners + EPSS/KEV"}},
		{ID: "CC7.2", Category: "CC", Name: "System operations — security incident detection",
			Status: "implemented", Evidence: []string{"UEBA + SIEM correlation + audit chain"}},
		{ID: "CC7.3", Category: "CC", Name: "System operations — incident response",
			Status: "implemented", Evidence: []string{"NIST 800-61r3 lifecycle + CIRCIA 72h reporting"}},
		{ID: "CC7.4", Category: "CC", Name: "System operations — incident recovery",
			Status: "implemented", Evidence: []string{"Tabletop exercise registry + RUNBOOK.md"}},
		{ID: "CC7.5", Category: "CC", Name: "System operations — recovery from disruption",
			Status: "partial", Evidence: []string{"Helm HPA + PDB; multi-region failover deployment-dependent"}},
		{ID: "CC8.1", Category: "CC", Name: "Change management — authorise, design, implement, test",
			Status: "implemented", Evidence: []string{"CODEOWNERS + branch protection + autopr SLA-based merge"}},
		{ID: "CC9.1", Category: "CC", Name: "Risk mitigation — vendor and business partner",
			Status: "implemented", Evidence: []string{"SBOM + VEX + CVE/EPSS/KEV enrichment + supply-chain signing"}},

		// ── Availability ─────────────────────────────────────────────
		{ID: "A1.1", Category: "A", Name: "Maintain capacity to meet objectives",
			Status: "implemented", Evidence: []string{"HPA autoscaling + k6 load tests in CI"}},
		{ID: "A1.2", Category: "A", Name: "Environmental protections, software, data backup",
			Status: "shared", Evidence: []string{"Backup strategy = customer responsibility (deploy/helm/values.yaml has no built-in backup)"}},

		// ── Confidentiality ──────────────────────────────────────────
		{ID: "C1.1", Category: "C", Name: "Information classified to support objectives",
			Status: "implemented", Evidence: []string{"Tenant data residency + per-tenant isolation"}},
		{ID: "C1.2", Category: "C", Name: "Disposal of confidential information",
			Status: "implemented", Evidence: []string{"DSR erasure with 30-day grace + cascading delete"}},

		// ── Processing Integrity (PI) ────────────────────────────────
		{ID: "PI1.1", Category: "PI", Name: "Quality information necessary to achieve objectives",
			Status: "implemented", Evidence: []string{"GET /api/v1/kpi/sanity assertions + sqrt scoring honesty"}},

		// ── Privacy ──────────────────────────────────────────────────
		{ID: "P1.1", Category: "P", Name: "Notice — privacy commitments and choices",
			Status: "implemented", Evidence: []string{"DSR /api/v1/data/* + Vietnam Decree 13/2023 + GDPR Art.15/17"}},
		{ID: "P4.1", Category: "P", Name: "Use, retention, disposal of personal information",
			Status: "implemented", Evidence: []string{"DSR erasure flow + 30-day grace + audit log"}},
	}
	implCount := 0
	for _, c := range criteria {
		if c.Status == "implemented" {
			implCount++
		}
	}
	jsonOK(w, map[string]any{
		"framework":          "SOC 2 Type I — AICPA Trust Services Criteria 2017 (rev. 2022)",
		"audit_type":         "Type I (design / readiness)",
		"attested_by":        "VSP-self",
		"attested_at":        time.Now().UTC().Format(time.RFC3339),
		"caveat":             "Self-attestation. Type I attestation requires AICPA-licensed CPA firm. Type II additionally requires 3-6 months of operating effectiveness evidence.",
		"criteria":           criteria,
		"summary": map[string]any{
			"total":          len(criteria),
			"implemented":    implCount,
			"readiness_pct":  (implCount * 100) / len(criteria),
		},
	})
}

// ── ISO 27001:2022 ─────────────────────────────────────────────────────────

type isoControl struct {
	ID       string   `json:"id"`       // e.g. "A.5.1"
	Theme    string   `json:"theme"`    // Organisational | People | Physical | Technological
	Name     string   `json:"name"`
	Status   string   `json:"status"`   // implemented | partial | shared
	Evidence []string `json:"evidence"`
}

func (h *Recognition) ISO27001Mapping(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.FromContext(r.Context()); !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// We map the highest-impact 30 of the 93 Annex A controls; the rest
	// either depend on the deploying organisation (Physical / People)
	// or are administrative procedures we have but don't expose via
	// API (e.g. "A.6.2 Terms and conditions of employment"). Auditor
	// guidance: the JSON output is a starting point, expand during
	// the Stage 1 readiness review.
	controls := []isoControl{
		// ── Organisational ───────────────────────────────────────────
		{ID: "A.5.1", Theme: "Organisational", Name: "Policies for information security",
			Status: "implemented", Evidence: []string{"docs/security/VULNERABILITY_DISCLOSURE_POLICY.md"}},
		{ID: "A.5.7", Theme: "Organisational", Name: "Threat intelligence",
			Status: "implemented", Evidence: []string{"VirusTotal + threat_intel feeds + EPSS/KEV"}},
		{ID: "A.5.10", Theme: "Organisational", Name: "Acceptable use of information",
			Status: "implemented", Evidence: []string{"Tenant residency policy + audit log"}},
		{ID: "A.5.15", Theme: "Organisational", Name: "Access control",
			Status: "implemented", Evidence: []string{"RBAC + Postgres RLS + per-tenant residency"}},
		{ID: "A.5.16", Theme: "Organisational", Name: "Identity management",
			Status: "implemented", Evidence: []string{"WebAuthn + TOTP + OIDC/SAML SSO"}},
		{ID: "A.5.17", Theme: "Organisational", Name: "Authentication information",
			Status: "implemented", Evidence: []string{"HIBP breach check + bcrypt cost 12 + IP lockout"}},
		{ID: "A.5.23", Theme: "Organisational", Name: "Information security for use of cloud services",
			Status: "implemented", Evidence: []string{"Vault secrets + cert pinning + data residency"}},
		{ID: "A.5.24", Theme: "Organisational", Name: "Incident management planning and preparation",
			Status: "implemented", Evidence: []string{"NIST 800-61r3 lifecycle + tabletop registry"}},
		{ID: "A.5.25", Theme: "Organisational", Name: "Assessment and decision on information security events",
			Status: "implemented", Evidence: []string{"ir_incidents severity + CIRCIA substantial flag"}},
		{ID: "A.5.26", Theme: "Organisational", Name: "Response to information security incidents",
			Status: "implemented", Evidence: []string{"SOAR playbooks + autopr remediation"}},
		{ID: "A.5.30", Theme: "Organisational", Name: "ICT readiness for business continuity",
			Status: "partial", Evidence: []string{"HPA + PDB ✓; backup/DR strategy customer-deployed"}},
		{ID: "A.5.34", Theme: "Organisational", Name: "Privacy and PII protection",
			Status: "implemented", Evidence: []string{"DSR + Decree 13/2023 + GDPR Art.15/17 + erasure grace"}},

		// ── People ───────────────────────────────────────────────────
		{ID: "A.6.3", Theme: "People", Name: "Information security awareness, education, training",
			Status: "shared", Evidence: []string{"Tabletop exercise registry; corporate training programme = customer"}},

		// ── Physical ─────────────────────────────────────────────────
		{ID: "A.7.1", Theme: "Physical", Name: "Physical security perimeters",
			Status: "shared", Evidence: []string{"Customer datacentre / cloud provider responsibility"}},
		{ID: "A.7.4", Theme: "Physical", Name: "Physical security monitoring",
			Status: "shared", Evidence: []string{"Customer datacentre / cloud provider responsibility"}},

		// ── Technological ────────────────────────────────────────────
		{ID: "A.8.1", Theme: "Technological", Name: "User endpoint devices",
			Status: "shared", Evidence: []string{"Customer endpoint policy"}},
		{ID: "A.8.2", Theme: "Technological", Name: "Privileged access rights",
			Status: "implemented", Evidence: []string{"admin role check + audit log + SECURITY_REVOKE on anomaly"}},
		{ID: "A.8.3", Theme: "Technological", Name: "Information access restriction",
			Status: "implemented", Evidence: []string{"Postgres RLS + per-tenant scope + 451 residency enforcement"}},
		{ID: "A.8.5", Theme: "Technological", Name: "Secure authentication",
			Status: "implemented", Evidence: []string{"WebAuthn + TOTP + JWT rotation + IP lockout"}},
		{ID: "A.8.7", Theme: "Technological", Name: "Protection against malware",
			Status: "implemented", Evidence: []string{"trivy + grype + cosign verify + secretcheck"}},
		{ID: "A.8.8", Theme: "Technological", Name: "Management of technical vulnerabilities",
			Status: "implemented", Evidence: []string{"26 scanners + EPSS/KEV + autopr remediation + POA&M"}},
		{ID: "A.8.9", Theme: "Technological", Name: "Configuration management",
			Status: "implemented", Evidence: []string{"Helm chart + IaC scanners (checkov/kics) + drift detection"}},
		{ID: "A.8.12", Theme: "Technological", Name: "Data leakage prevention",
			Status: "implemented", Evidence: []string{"gitleaks + secretcheck + trufflehog + DSR controls"}},
		{ID: "A.8.13", Theme: "Technological", Name: "Information backup",
			Status: "shared", Evidence: []string{"Customer backup strategy; helm has no built-in backup"}},
		{ID: "A.8.15", Theme: "Technological", Name: "Logging",
			Status: "implemented", Evidence: []string{"audit_log SHA-256 hash chained + zerolog structured + RLS"}},
		{ID: "A.8.16", Theme: "Technological", Name: "Monitoring activities",
			Status: "implemented", Evidence: []string{"UEBA 7 anomaly types + KPI watchdog + ConMon score"}},
		{ID: "A.8.20", Theme: "Technological", Name: "Networks security",
			Status: "implemented", Evidence: []string{"NetworkPolicy DNS-only egress + cert pinning + TLS 1.3"}},
		{ID: "A.8.23", Theme: "Technological", Name: "Web filtering",
			Status: "shared", Evidence: []string{"Customer egress proxy / WAF responsibility"}},
		{ID: "A.8.24", Theme: "Technological", Name: "Use of cryptography",
			Status: "implemented", Evidence: []string{"ECDSA P-256 signing + bcrypt cost 12 + TLS 1.3 + Vault rotation"}},
		{ID: "A.8.25", Theme: "Technological", Name: "Secure development life cycle",
			Status: "implemented", Evidence: []string{"NIST SSDF mapped + 26 scanners in CI + signed releases"}},
		{ID: "A.8.28", Theme: "Technological", Name: "Secure coding",
			Status: "implemented", Evidence: []string{"golangci-lint with gosec + nilerr + sqlclosecheck + CODEOWNERS"}},
	}
	implCount := 0
	for _, c := range controls {
		if c.Status == "implemented" {
			implCount++
		}
	}
	jsonOK(w, map[string]any{
		"framework":     "ISO/IEC 27001:2022 Annex A",
		"controls_total": 93,
		"controls_mapped": len(controls),
		"attested_by":    "VSP-self",
		"attested_at":    time.Now().UTC().Format(time.RFC3339),
		"caveat":         "Self-attestation across the 30 highest-impact Annex A controls. ISO 27001 certification requires accredited certification body + 3-stage audit cycle (initial / surveillance / recertification). Use this mapping as Stage 1 readiness input.",
		"controls":       controls,
		"summary": map[string]any{
			"implemented_of_mapped": implCount,
			"mapped_pct":            (len(controls) * 100) / 93,
		},
	})
}
