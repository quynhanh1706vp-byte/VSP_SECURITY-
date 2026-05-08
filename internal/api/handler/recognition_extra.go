// Package handler — additional framework mappings (Sprint 10.1).
//
// Extends recognition_maps.go (SOC 2 + ISO 27001) with four more
// frameworks customers / regulators commonly ask about:
//
//   • PCI-DSS 4.0  (Payment Card Industry Data Security Standard)
//   • NIS2        (EU Network and Information Security Directive 2)
//   • HITRUST CSF (healthcare-aligned cross-mapping)
//   • CCPA / CPRA (California Consumer Privacy Act / Privacy Rights Act)
//
// Each endpoint returns the same shape: framework metadata + mapped
// controls + evidence pointers. All self-attested — third-party
// validation comes from the appropriate certification body (PCI QSA,
// HITRUST CSF Assessor Organization, etc.).
//
// Endpoints:
//   GET /api/v1/recognition/pci-dss-mapping
//   GET /api/v1/recognition/nis2-mapping
//   GET /api/v1/recognition/hitrust-mapping
//   GET /api/v1/recognition/ccpa-mapping
package handler

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
)

type frameworkControl struct {
	ID       string   `json:"id"`
	Theme    string   `json:"theme,omitempty"`
	Name     string   `json:"name"`
	Status   string   `json:"status"` // implemented | partial | shared | n/a
	Evidence []string `json:"evidence"`
}

func writeFrameworkMapping(w http.ResponseWriter, r *http.Request,
	framework, caveat string, controls []frameworkControl) {

	if _, ok := auth.FromContext(r.Context()); !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	implCount := 0
	for _, c := range controls {
		if c.Status == "implemented" {
			implCount++
		}
	}
	jsonOK(w, map[string]any{
		"framework":         framework,
		"attested_by":       "VSP-self",
		"attested_at":       time.Now().UTC().Format(time.RFC3339),
		"caveat":            caveat,
		"controls":          controls,
		"controls_total":    len(controls),
		"controls_impl":     implCount,
	})
}

// PCI-DSS 4.0 — relevant because VSP imports stripe-go for PRO
// billing. Even though customers' card data flows directly to Stripe
// (we never store PAN), we sit in the cardholder-data-environment
// (CDE) trust boundary as a "service provider".
func (h *Recognition) PCIDSSMapping(w http.ResponseWriter, r *http.Request) {
	controls := []frameworkControl{
		{ID: "1.1", Theme: "Network Security",
			Name: "Processes and mechanisms for installing/maintaining network security controls",
			Status: "implemented",
			Evidence: []string{"deploy/helm/templates/networkpolicy.yaml DNS-only egress + per-tenant residency"}},
		{ID: "2.1", Theme: "System Hardening",
			Name: "Apply secure configurations to all system components",
			Status: "implemented",
			Evidence: []string{"deploy/helm/values.yaml restricted PSP + non-root + read-only FS + drop ALL caps"}},
		{ID: "3.1", Theme: "Stored Account Data",
			Name: "Storage of cardholder data is kept to a minimum",
			Status: "implemented",
			Evidence: []string{"VSP never stores PAN; Stripe Elements tokenize at browser; only stripe customer_id persisted"}},
		{ID: "4.1", Theme: "Transmitted Data",
			Name: "Strong cryptography during transmission",
			Status: "implemented",
			Evidence: []string{"TLS 1.3 minimum + cert pinning on outbound webhooks + HMAC-signed payloads"}},
		{ID: "5.1", Theme: "Anti-Malware",
			Name: "Protect all systems from malicious software",
			Status: "implemented",
			Evidence: []string{"trivy + grype + cosign verify + secretcheck + 26-tool scan pipeline"}},
		{ID: "6.1", Theme: "Software Development",
			Name: "Develop secure systems and software",
			Status: "implemented",
			Evidence: []string{"NIST SSDF mapped + CODEOWNERS + 26 scanners in CI + signed releases"}},
		{ID: "7.1", Theme: "Restrict Access",
			Name: "Restrict access by business need-to-know",
			Status: "implemented",
			Evidence: []string{"Postgres RLS + RBAC roles + per-tenant residency + admin gating"}},
		{ID: "8.1", Theme: "Identify Users",
			Name: "User identification and authentication",
			Status: "implemented",
			Evidence: []string{"WebAuthn + TOTP + HIBP + IP lockout + UEBA-driven session revoke"}},
		{ID: "9.1", Theme: "Restrict Physical Access",
			Name: "Physical access to cardholder data is restricted",
			Status: "shared",
			Evidence: []string{"Customer datacentre / cloud provider responsibility"}},
		{ID: "10.1", Theme: "Logging",
			Name: "Log all access to system components and CHD",
			Status: "implemented",
			Evidence: []string{"audit_log SHA-256 hash chain + every admin action audit-logged + RLS on audit_log"}},
		{ID: "11.1", Theme: "Test Security",
			Name: "Test security of systems and networks regularly",
			Status: "implemented",
			Evidence: []string{"ConMon + 26 scanners + tests/load/k6_slo.js + tabletop registry"}},
		{ID: "12.1", Theme: "Information Security Policy",
			Name: "A comprehensive InfoSec policy is maintained",
			Status: "implemented",
			Evidence: []string{"docs/security/VULNERABILITY_DISCLOSURE_POLICY.md + RISK_REGISTER.md"}},
	}
	writeFrameworkMapping(w, r,
		"PCI-DSS 4.0 (released March 2022, mandatory March 2025)",
		"VSP is a Service Provider in the CDE — we never store PAN data. "+
			"Self-attestation of the 12 high-level requirements; full QSA "+
			"audit required for Level 1 Service Provider designation.",
		controls)
}

// NIS2 — EU Network and Information Security Directive 2, transposed
// into national law by EU member states by Oct 2024. Relevant if VSP
// has any EU customer or operates in the EU. The directive applies
// 7 governance + technical security measures (Article 21).
func (h *Recognition) NIS2Mapping(w http.ResponseWriter, r *http.Request) {
	controls := []frameworkControl{
		{ID: "Art21(2)(a)", Name: "Risk analysis and information system security policies",
			Status: "implemented",
			Evidence: []string{"docs/audit/RISK_REGISTER.md + docs/SECURITY_DECISIONS.md"}},
		{ID: "Art21(2)(b)", Name: "Incident handling",
			Status: "implemented",
			Evidence: []string{"NIST 800-61r3 lifecycle + CIRCIA 72h reporting + tabletop registry"}},
		{ID: "Art21(2)(c)", Name: "Business continuity and crisis management",
			Status: "partial",
			Evidence: []string{"Helm HPA + PDB ✓; backup/DR strategy customer-deployed"}},
		{ID: "Art21(2)(d)", Name: "Supply chain security",
			Status: "implemented",
			Evidence: []string{"cosign signed images + SLSA L3 provenance + syft SBOM + osvscanner enrichment"}},
		{ID: "Art21(2)(e)", Name: "Security in network and information system acquisition",
			Status: "implemented",
			Evidence: []string{"go.sum pinning + dependabot review + 7 SCA scanners"}},
		{ID: "Art21(2)(f)", Name: "Policies and procedures to assess effectiveness",
			Status: "implemented",
			Evidence: []string{"GET /api/v1/kpi/sanity (HTTP 409 release blocker) + KPI watchdog + improvement metrics"}},
		{ID: "Art21(2)(g)", Name: "Basic cyber hygiene practices and security training",
			Status: "shared",
			Evidence: []string{"VSP provides tooling; customer training programme out of scope"}},
		{ID: "Art21(2)(h)", Name: "Cryptography and encryption policies",
			Status: "implemented",
			Evidence: []string{"ECDSA P-256 + bcrypt cost 12 + TLS 1.3 + Vault rotation + WebAuthn"}},
		{ID: "Art21(2)(i)", Name: "Human resources security, access control, asset management",
			Status: "implemented",
			Evidence: []string{"WebAuthn + TOTP + RBAC + per-tenant residency + DSR/erasure"}},
		{ID: "Art21(2)(j)", Name: "Multi-factor authentication or continuous authentication",
			Status: "implemented",
			Evidence: []string{"WebAuthn (FIDO2 Passkey) + TOTP + IP lockout + UEBA continuous-auth signals"}},
		{ID: "Art23", Name: "Reporting obligations to CSIRT (24h early warning, 72h notification, 1mo final report)",
			Status: "implemented",
			Evidence: []string{"ir_incidents lifecycle + circia_reports table + CIRCIA 72h workflow"}},
	}
	writeFrameworkMapping(w, r,
		"NIS2 Directive (EU) 2022/2555",
		"Self-attestation against the 10 governance/technical measures of "+
			"Article 21 + Article 23 reporting. Full compliance verified "+
			"by national supervisory authority of the relevant EU member "+
			"state on registration.",
		controls)
}

// HITRUST CSF — common in healthcare (US-centric). Cross-maps NIST,
// ISO 27001, HIPAA, PCI-DSS, GDPR. We surface the highest-impact
// controls; full HITRUST CSF assessment requires HITRUST-CSF Assessor.
func (h *Recognition) HITRUSTMapping(w http.ResponseWriter, r *http.Request) {
	controls := []frameworkControl{
		{ID: "01.a", Theme: "Information Security Management",
			Name: "Information Security Management Program",
			Status: "implemented",
			Evidence: []string{"docs/security/* + NIST CSF profile endpoint"}},
		{ID: "01.b", Theme: "Information Security Management",
			Name: "Management Approval of Information Security Policy",
			Status: "implemented",
			Evidence: []string{"VDP signed; risk register reviewed quarterly"}},
		{ID: "06.a", Theme: "Compliance",
			Name: "Identification of Applicable Legislation",
			Status: "implemented",
			Evidence: []string{"docs/COMPLIANCE_MATRIX.md tracks 18 frameworks"}},
		{ID: "06.b", Theme: "Compliance",
			Name: "Privacy and Protection of Personally Identifiable Information",
			Status: "implemented",
			Evidence: []string{"DSR (Art.15+17) + Decree 13/2023 + GDPR + erasure with 30-day grace"}},
		{ID: "07.a", Theme: "Operations Management",
			Name: "Documented Operating Procedures",
			Status: "implemented",
			Evidence: []string{"docs/RUNBOOK.md + AUDIT_ENGAGEMENT_GUIDE.md + 6 operational endpoints"}},
		{ID: "08.a", Theme: "Operations Management",
			Name: "Network Controls",
			Status: "implemented",
			Evidence: []string{"NetworkPolicy DNS-only egress + cert pinning + TLS 1.3"}},
		{ID: "09.a", Theme: "Operations Management",
			Name: "Network Security Management",
			Status: "implemented",
			Evidence: []string{"netcap L2-L7 + sslscan + nmap + sslscan in pipeline"}},
		{ID: "09.s", Theme: "Operations Management",
			Name: "Information Exchange Policies and Procedures",
			Status: "implemented",
			Evidence: []string{"Vietnam Decree 53/2022 residency + 451 enforcement on cross-border"}},
		{ID: "10.a", Theme: "Information Systems Acquisition",
			Name: "Security Requirements Analysis and Specification",
			Status: "implemented",
			Evidence: []string{"NIST SSDF mapped + CISA SSDF auto-form + 26 scanners"}},
		{ID: "11.a", Theme: "Information Security Incident Management",
			Name: "Reporting Information Security Events",
			Status: "implemented",
			Evidence: []string{"/.well-known/security.txt + VDP + /api/v1/security/disclose"}},
		{ID: "12.a", Theme: "Business Continuity",
			Name: "Including Information Security in Business Continuity Process",
			Status: "partial",
			Evidence: []string{"Tabletop registry + Helm HPA/PDB; full BCP customer-owned"}},
	}
	writeFrameworkMapping(w, r,
		"HITRUST CSF v11 (cross-mapped)",
		"Self-attestation across 11 highest-impact HITRUST CSF control "+
			"families. Full HITRUST i1 / r2 assessment requires a "+
			"HITRUST-CSF Assessor Organization (e.g. Coalfire Federal).",
		controls)
}

// CCPA / CPRA — California Consumer Privacy Act + Privacy Rights Act
// 2020. Required by any business doing >$25M revenue or handling
// >100k California consumers' data. Most US-facing customers ask.
func (h *Recognition) CCPAMapping(w http.ResponseWriter, r *http.Request) {
	controls := []frameworkControl{
		{ID: "1798.100", Name: "Right to Know — categories of personal information collected",
			Status: "implemented",
			Evidence: []string{"DSR data export endpoint + privacy notice in /trust/"}},
		{ID: "1798.105", Name: "Right to Delete personal information",
			Status: "implemented",
			Evidence: []string{"DSR /api/v1/data/erasure with 30-day grace + token-confirmed + cancellable"}},
		{ID: "1798.106", Name: "Right to Correct inaccurate personal information",
			Status: "implemented",
			Evidence: []string{"User profile update endpoints + audit-logged correction events"}},
		{ID: "1798.110", Name: "Right to Know — specific personal information collected",
			Status: "implemented",
			Evidence: []string{"DSR /api/v1/data/export returns full tenant data dump"}},
		{ID: "1798.115", Name: "Right to Know — disclosure to third parties",
			Status: "implemented",
			Evidence: []string{"docs/security/VULNERABILITY_DISCLOSURE_POLICY.md + Trust Center frameworks table"}},
		{ID: "1798.120", Name: "Right to Opt-Out of Sale or Sharing",
			Status: "n/a",
			Evidence: []string{"VSP does not sell or share personal data; \"Do Not Sell\" not applicable"}},
		{ID: "1798.121", Name: "Right to Limit Use of Sensitive Personal Information",
			Status: "implemented",
			Evidence: []string{"PII-classified fields gated behind admin role + audit log"}},
		{ID: "1798.125", Name: "Non-Discrimination for exercising rights",
			Status: "implemented",
			Evidence: []string{"DSR endpoints available to all authenticated users; no service degradation"}},
		{ID: "1798.130", Name: "Verifiable consumer requests",
			Status: "implemented",
			Evidence: []string{"DSR token-confirmation + admin role for erasure + 30-day grace for revocation"}},
		{ID: "1798.140", Name: "Required disclosures in privacy policy",
			Status: "implemented",
			Evidence: []string{"Trust Center page + VDP + Compliance Matrix"}},
		{ID: "1798.150", Name: "Civil action for data breach (private right of action)",
			Status: "partial",
			Evidence: []string{"Audit chain SHA-256 + breach notification workflow; legal contracting customer-owned"}},
	}
	writeFrameworkMapping(w, r,
		"CCPA 2018 + CPRA 2020 (California Civil Code §§1798.100-1798.199)",
		"Self-attestation. Many CCPA controls overlap with GDPR — VSP's "+
			"DSR + erasure flow satisfies both. \"Right to Opt-Out of Sale\" "+
			"is N/A because VSP does not sell personal data.",
		controls)
}
