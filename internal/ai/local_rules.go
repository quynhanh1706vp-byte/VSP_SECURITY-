package ai

import (
	"strings"
)

// LocalAdvise produces a deterministic rule-based remediation when no
// LLM API is available (air-gap mode, missing API key, or admin opted
// for local-only). The output structure mirrors the LLM JSON format so
// the UI renders identically regardless of source.
func LocalAdvise(framework, controlID, findingSummary string) AdviseResponse {
	tmpl := matchTemplate(controlID, findingSummary)

	return AdviseResponse{
		Remediation: tmpl.Remediation,
		EffortHours: tmpl.Effort,
		Evidence:    tmpl.Evidence,
		References:  tmpl.References,
		RiskAccept:  tmpl.RiskAccept,
		Source:      "local",
	}
}

type localTemplate struct {
	Remediation string
	Effort      EffortHours
	Evidence    string
	References  []string
	RiskAccept  string
}

// matchTemplate routes to a specific template based on control ID
// patterns and finding keywords. The set is intentionally compact —
// it covers the most common control families seen in pilots.
func matchTemplate(controlID, findingSummary string) localTemplate {
	id := strings.ToUpper(controlID)
	finding := strings.ToLower(findingSummary)

	// Access Control family
	if strings.HasPrefix(id, "AC-") || strings.Contains(finding, "access control") || strings.Contains(finding, "rbac") {
		return tmplAccessControl(id)
	}
	// Audit & Accountability
	if strings.HasPrefix(id, "AU-") || strings.Contains(finding, "audit log") || strings.Contains(finding, "logging") {
		return tmplAudit(id)
	}
	// System & Information Integrity (vulns)
	if strings.HasPrefix(id, "SI-") || strings.Contains(finding, "vulnerab") || strings.Contains(finding, "cve") {
		return tmplVulnerability(id)
	}
	// Configuration Management
	if strings.HasPrefix(id, "CM-") || strings.Contains(finding, "configuration") || strings.Contains(finding, "drift") {
		return tmplConfigMgmt(id)
	}
	// Identification & Authentication
	if strings.HasPrefix(id, "IA-") || strings.Contains(finding, "mfa") || strings.Contains(finding, "password") {
		return tmplAuth(id)
	}
	// Risk Assessment
	if strings.HasPrefix(id, "RA-") {
		return tmplRiskAssessment(id)
	}
	// SBV-specific
	if strings.Contains(id, "TT09") || strings.Contains(id, "SBV") {
		return tmplSBV(id)
	}

	// Generic fallback
	return tmplGeneric(id)
}

func tmplVulnerability(id string) localTemplate {
	return localTemplate{
		Remediation: `### Vulnerability remediation

1. **Identify the affected component** — run ` + "`vsp scan --mode SCA --target <repo>`" + ` and filter findings by CVE.
2. **Pin to patched version** — update the dependency manifest:

` + "```diff" + `
-    "package": "1.4.2"
+    "package": "1.4.5"
` + "```" + `

3. **Rebuild and re-scan** to confirm the gate passes.
4. **Sign-off** by the security lead before merging.`,
		Effort: EffortHours{Junior: 4, Mid: 2, Senior: 1},
		Evidence: "Vulnerability tracked in POA&M item #<TBD>. Patched dependency in commit <COMMIT_HASH>. Re-scan evidence: scan run <RUN_ID> shows the previously-failing gate now passing.",
		References: []string{id, "SI-2", "RA-5", "CM-8"},
		RiskAccept: "If patching is deferred, document a compensating control (e.g., WAF rule blocking the attack vector) and obtain written CISO acceptance with a 30-day re-evaluation date.",
	}
}

func tmplAccessControl(id string) localTemplate {
	return localTemplate{
		Remediation: `### Access control remediation

1. **Audit current role assignments** — export from your IdP (Okta/Entra/Keycloak) and reconcile against the system access matrix.
2. **Apply principle of least privilege** — for each role, remove permissions not in the documented job function.
3. **Enable just-in-time elevation** for privileged operations rather than standing access.
4. **Review every 90 days** with the resource owner.`,
		Effort: EffortHours{Junior: 8, Mid: 4, Senior: 2},
		Evidence: "Access matrix reviewed and updated in commit <HASH>. JIT elevation configured for the privileged-operator role. Quarterly review scheduled in compliance calendar.",
		References: []string{id, "AC-2", "AC-6", "ISO 27001 A.5.15"},
		RiskAccept: "If JIT cannot be implemented in this cycle, document the standing-access exception with a quarterly review and a 12-month migration plan.",
	}
}

func tmplAudit(id string) localTemplate {
	return localTemplate{
		Remediation: `### Audit logging remediation

1. **Enable structured logging** for the affected service. Output should be JSON with fields: ` + "`timestamp, actor, action, resource, outcome, source_ip`" + `.
2. **Forward to SIEM** — configure syslog (TCP 10515) or HTTP endpoint to your SIEM.
3. **Retention policy** — store audit logs for the regulatory period (FedRAMP: 3 years, CMMC: indefinitely, SBV: 10 years).
4. **Tamper protection** — append-only with cryptographic chaining of log entries.`,
		Effort: EffortHours{Junior: 16, Mid: 8, Senior: 4},
		Evidence: "Structured logging deployed in release <VERSION>. SIEM forwarding configured in commit <HASH>. Retention policy documented at <POLICY_URL>.",
		References: []string{id, "AU-2", "AU-6", "AU-11", "ISO 27001 A.8.15"},
		RiskAccept: "If retention period cannot be met immediately, document interim retention with monthly increases until target is reached.",
	}
}

func tmplConfigMgmt(id string) localTemplate {
	return localTemplate{
		Remediation: `### Configuration management remediation

1. **Establish baseline** — capture current production config in version control (Git).
2. **Detect drift** — schedule daily ` + "`vsp scan --mode CONFIG`" + ` runs and alert on diffs.
3. **Remediate drift** — restore to baseline within 24 hours or update the baseline through change-control approval.
4. **Approval gate** — require security review for baseline changes affecting Annex A control coverage.`,
		Effort: EffortHours{Junior: 12, Mid: 6, Senior: 3},
		Evidence: "Baseline config committed at <HASH>. Drift-detection scheduled in ConMon (schedule ID <SCH_ID>). Last scheduled run: <DATE>.",
		References: []string{id, "CM-2", "CM-3", "CM-6", "ISO 27001 A.8.9"},
		RiskAccept: "Document any approved deviation from baseline in the configuration register with re-evaluation date.",
	}
}

func tmplAuth(id string) localTemplate {
	return localTemplate{
		Remediation: `### Authentication strengthening

1. **Enable MFA** for all administrative accounts. Acceptable factors: TOTP, FIDO2 hardware keys, push notifications.
2. **Disable password-only auth** for any production resource. SSH should require keys; web apps should require SSO.
3. **Rotate credentials** older than the policy period (FedRAMP: 60 days for privileged accounts).
4. **Disable shared accounts** — every action must trace to a named identity.`,
		Effort: EffortHours{Junior: 8, Mid: 4, Senior: 2},
		Evidence: "MFA enrolled at 100% for admin role (audit query in evidence/auth_mfa_<DATE>.csv). Password rotation policy enforced via IdP.",
		References: []string{id, "IA-2", "IA-5", "ISO 27001 A.5.16, A.5.17"},
		RiskAccept: "Service accounts that cannot use MFA must be documented, scoped to least privilege, and rotated every 30 days.",
	}
}

func tmplRiskAssessment(id string) localTemplate {
	return localTemplate{
		Remediation: `### Risk assessment remediation

1. **Run the full vulnerability scan** — ` + "`vsp scan --mode FULL --target <scope>`" + `.
2. **Triage by CVSS + exploitability** — critical and high findings require POA&M entries within 30 days.
3. **Risk register** — document each accepted risk with compensating controls and re-evaluation date.
4. **Quarterly review** with the system owner.`,
		Effort: EffortHours{Junior: 6, Mid: 3, Senior: 2},
		Evidence: "Vulnerability scan run <RUN_ID> covered <N> assets. POA&M items created for all findings rated High or above.",
		References: []string{id, "RA-3", "RA-5", "ISO 27001 A.5.7"},
		RiskAccept: "Risk acceptance must be signed by the system owner with documented compensating controls and a re-evaluation date no more than 90 days out.",
	}
}

func tmplSBV(id string) localTemplate {
	return localTemplate{
		Remediation: `### Khắc phục theo TT 09/2020 NHNN

1. **Phân loại lại hệ thống thông tin** theo Điều 12 — xác định cấp độ đúng (3 hoặc 4) dựa trên giá trị tài sản và mức độ ảnh hưởng.
2. **Kiểm soát truy cập** — áp dụng MFA cho mọi tài khoản truy cập hệ thống cấp 3 trở lên (Điều 18).
3. **Giám sát liên tục** — kích hoạt SIEM forwarding và lưu trữ log tối thiểu 10 năm theo TT 09 Điều 22.
4. **Báo cáo định kỳ** — chuẩn bị báo cáo quý nộp lên Thanh tra Giám sát NHNN theo Điều 30.

### Remediation per SBV TT 09/2020

1. Reclassify the information system per Article 12.
2. Enable MFA for all level-3+ accounts (Article 18).
3. Activate SIEM forwarding with 10-year retention (Article 22).
4. Prepare quarterly compliance report for SBV inspectorate (Article 30).`,
		Effort: EffortHours{Junior: 24, Mid: 12, Senior: 6},
		Evidence: "Hệ thống được phân loại lại tại <DATE>. MFA enrollment 100% xác minh tại <REPORT>. Báo cáo quý <Q> sẵn sàng nộp.",
		References: []string{id, "TT_09_2020_Đ12", "TT_09_2020_Đ18", "TT_09_2020_Đ22", "ISO 27001 A.5.18"},
		RiskAccept: "Mọi ngoại lệ phải có phê duyệt của Tổng giám đốc, kèm phương án giảm thiểu và thời gian khắc phục không quá 90 ngày.",
	}
}

func tmplGeneric(id string) localTemplate {
	return localTemplate{
		Remediation: `### Generic remediation guidance

1. **Reproduce the finding** in a non-production environment.
2. **Identify the root cause** — code, configuration, or process gap.
3. **Implement the fix** with peer review.
4. **Re-scan** to confirm the gate passes.
5. **Document** the change in the change-management system.`,
		Effort: EffortHours{Junior: 8, Mid: 4, Senior: 2},
		Evidence: "Finding remediation tracked in ticket <TICKET_ID>. Code/config change in commit <HASH>. Re-scan evidence: run <RUN_ID> shows gate passing.",
		References: []string{id},
		RiskAccept: "If remediation cannot be completed within policy timeline, document an interim compensating control and a target completion date approved by the system owner.",
	}
}
