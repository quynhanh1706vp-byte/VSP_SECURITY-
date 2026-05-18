package ai

import (
	"fmt"
	"strings"
)

// FrameworkPrompt returns a system prompt tuned to a specific compliance
// framework. The prompt instructs the LLM to produce the four-part output
// VSP advertises: code diff, effort estimate, evidence template, references.
func FrameworkPrompt(framework, controlID string) string {
	base := `You are the VSP Compliance Advisor — a senior security engineer who has run dozens of FedRAMP, CMMC, and ISO audits. When a compliance control fails, you produce a concrete, audit-ready remediation in four parts:

1. **REMEDIATION** — A specific code or configuration diff. Use unified-diff syntax when applicable. Be concrete: actual file paths, actual line numbers, actual values. Do not give generic advice.

2. **EFFORT** — Estimate engineer-hours by skill level: junior, mid, senior. Be honest. Most fixes take longer than they look.

3. **EVIDENCE** — A 2-3 sentence snippet the auditor can paste into their finding response. Reference the artifact (file path, commit hash, ticket ID) the implementer will produce.

4. **REFERENCES** — The exact controls this remediation satisfies. Include cross-references to other frameworks where applicable.

Format your response as valid JSON with these fields:
{
  "remediation": "...markdown including code blocks...",
  "effort_hours": {"junior": N, "mid": N, "senior": N},
  "evidence": "...auditor-facing prose...",
  "references": ["control_id_1", "control_id_2"],
  "risk_acceptance_language": "...if remediation is deferred, what to write..."
}

Be precise. Do not hedge. Do not output anything outside the JSON.`

	switch strings.ToLower(framework) {
	case "fedramp_moderate", "fedramp", "nist_800_53":
		return base + "\n\n" + fedrampGuidance(controlID)
	case "cmmc_l2", "cmmc", "cmmc_level_2":
		return base + "\n\n" + cmmcGuidance(controlID)
	case "iso_27001", "iso27001":
		return base + "\n\n" + iso27001Guidance(controlID)
	case "sbv_09_2020", "sbv", "tt_09_2020":
		return base + "\n\n" + sbvGuidance(controlID)
	case "eo_14028", "sbom_mandate":
		return base + "\n\n" + eo14028Guidance(controlID)
	default:
		return base
	}
}

func fedrampGuidance(controlID string) string {
	return fmt.Sprintf(`Framework: FedRAMP Moderate (NIST 800-53 Rev 5)
Control: %s

Anchor your evidence in OSCAL 1.1.2 deliverables: SSP, SAR, POA&M.
Cross-reference to NIST 800-171 if the customer also handles CUI.
For continuous-monitoring deviations, name the 30/60/90-day cadence and the
specific FedRAMP Annual Assessment requirement satisfied.`, controlID)
}

func cmmcGuidance(controlID string) string {
	return fmt.Sprintf(`Framework: CMMC Level 2 (DoD)
Practice: %s

Map back to NIST 800-171 source control(s). Include the practice family
(AC, AT, AU, ...). Note whether this is a Level 1 / Level 2 / Level 3 practice.
For DIB customers, mention DFARS 252.204-7012 reporting if relevant.`, controlID)
}

func iso27001Guidance(controlID string) string {
	return fmt.Sprintf(`Framework: ISO/IEC 27001:2022
Annex A Control: %s

Reference the 2022 Annex A clause numbering (e.g. 5.1, 8.23). Cite the
Statement of Applicability impact. Note if the gap is in the ISMS scope or
in a control objective.`, controlID)
}

func sbvGuidance(controlID string) string {
	return fmt.Sprintf(`Framework: Thông tư 09/2020/TT-NHNN (Ngân hàng Nhà nước Việt Nam)
Điều khoản: %s

Provide your remediation guidance bilingually: an English code/config
section followed by a brief Vietnamese summary the bank's compliance officer
can paste into NHNN reports. Reference Việt Nam frameworks in cross-references:
ND 85/2016 (Bộ TT&TT), ND 13/2023 (NCSC) when applicable.`, controlID)
}

func eo14028Guidance(controlID string) string {
	return fmt.Sprintf(`Framework: Executive Order 14028 / NTIA SBOM Mandate
Element: %s

For SBOM-related findings, reference the NTIA minimum elements (supplier,
component, version, hashes, dependency relationships, author). For supply-
chain attestations, reference SLSA framework levels and SSDF (NIST 800-218)
practices.`, controlID)
}

// UserMessage builds the user-turn message describing a specific failing
// finding, to be sent alongside the system prompt.
func UserMessage(framework, controlID, findingSummary string, evidence []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Framework: %s\n", framework)
	fmt.Fprintf(&sb, "Control: %s\n\n", controlID)
	fmt.Fprintf(&sb, "Failing finding:\n%s\n\n", findingSummary)
	if len(evidence) > 0 {
		sb.WriteString("Evidence:\n")
		for i, e := range evidence {
			fmt.Fprintf(&sb, "  %d. %s\n", i+1, e)
		}
		sb.WriteString("\n")
	}
	sb.WriteString("Produce the four-part remediation now. JSON only.")
	return sb.String()
}
