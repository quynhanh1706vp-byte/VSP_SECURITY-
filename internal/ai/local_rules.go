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
	// System & Communications
	if strings.HasPrefix(id, "SC-") || strings.Contains(finding, "encrypt") || strings.Contains(finding, "tls") || strings.Contains(finding, "ssl") || strings.Contains(finding, "certificate") || strings.Contains(finding, "https") || strings.Contains(finding, "network") {
		return tmplSystemComms(id)
	}
	// Incident Response
	if strings.HasPrefix(id, "IR-") || strings.Contains(finding, "incident") || strings.Contains(finding, "breach") {
		return tmplIncidentResponse(id)
	}
	// Contingency Planning
	if strings.HasPrefix(id, "CP-") || strings.Contains(finding, "backup") || strings.Contains(finding, "recovery") {
		return tmplContingency(id)
	}
	// Physical
	if strings.HasPrefix(id, "PE-") || strings.Contains(finding, "physical") || strings.Contains(finding, "media") {
		return tmplPhysical(id)
	}
	// Supply Chain
	if strings.HasPrefix(id, "SR-") || strings.HasPrefix(id, "SA-") || strings.Contains(finding, "supply chain") || strings.Contains(finding, "dependency") {
		return tmplSupplyChain(id)
	}
	// Secrets
	if strings.Contains(finding, "secret") || strings.Contains(finding, "api key") || strings.Contains(finding, "token") || strings.Contains(finding, "credential") {
		return tmplSecrets(id)
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
		Effort:     EffortHours{Junior: 4, Mid: 2, Senior: 1},
		Evidence:   "Vulnerability tracked in POA&M item #<TBD>. Patched dependency in commit <COMMIT_HASH>. Re-scan evidence: scan run <RUN_ID> shows the previously-failing gate now passing.",
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
		Effort:     EffortHours{Junior: 8, Mid: 4, Senior: 2},
		Evidence:   "Access matrix reviewed and updated in commit <HASH>. JIT elevation configured for the privileged-operator role. Quarterly review scheduled in compliance calendar.",
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
		Effort:     EffortHours{Junior: 16, Mid: 8, Senior: 4},
		Evidence:   "Structured logging deployed in release <VERSION>. SIEM forwarding configured in commit <HASH>. Retention policy documented at <POLICY_URL>.",
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
		Effort:     EffortHours{Junior: 12, Mid: 6, Senior: 3},
		Evidence:   "Baseline config committed at <HASH>. Drift-detection scheduled in ConMon (schedule ID <SCH_ID>). Last scheduled run: <DATE>.",
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
		Effort:     EffortHours{Junior: 8, Mid: 4, Senior: 2},
		Evidence:   "MFA enrolled at 100% for admin role (audit query in evidence/auth_mfa_<DATE>.csv). Password rotation policy enforced via IdP.",
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
		Effort:     EffortHours{Junior: 6, Mid: 3, Senior: 2},
		Evidence:   "Vulnerability scan run <RUN_ID> covered <N> assets. POA&M items created for all findings rated High or above.",
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
		Effort:     EffortHours{Junior: 24, Mid: 12, Senior: 6},
		Evidence:   "Hệ thống được phân loại lại tại <DATE>. MFA enrollment 100% xác minh tại <REPORT>. Báo cáo quý <Q> sẵn sàng nộp.",
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
		Effort:     EffortHours{Junior: 8, Mid: 4, Senior: 2},
		Evidence:   "Finding remediation tracked in ticket <TICKET_ID>. Code/config change in commit <HASH>. Re-scan evidence: run <RUN_ID> shows gate passing.",
		References: []string{id},
		RiskAccept: "If remediation cannot be completed within policy timeline, document an interim compensating control and a target completion date approved by the system owner.",
	}
}

func tmplSystemComms(id string) localTemplate {
	return localTemplate{
		Remediation: `### System & communications protection

1. **Enable TLS 1.2+ everywhere** — audit all service-to-service and client-to-server connections.
2. **Enforce network segmentation** — separate production, staging, and development VPCs/VLANs.
3. **Deploy WAF rules** for public-facing endpoints; block OWASP Top 10 patterns.
4. **Encrypt data at rest** — verify all S3 buckets, RDS instances, and volumes use AES-256.
5. **Certificate rotation** — automate via Let's Encrypt or internal PKI; alert 30 days before expiry.`,
		Effort:     EffortHours{Junior: 16, Mid: 8, Senior: 4},
		Evidence:   "TLS audit completed <DATE>. WAF rules deployed in <ENV>. Encryption-at-rest verified in scan run <RUN_ID>.",
		References: []string{id, "SC-8", "SC-13", "SC-28", "ISO 27001 A.8.24"},
		RiskAccept: "Any unencrypted channel must be documented with a compensating control (e.g., VPN tunnel) and remediated within 30 days.",
	}
}

func tmplIncidentResponse(id string) localTemplate {
	return localTemplate{
		Remediation: `### Incident response remediation

1. **Activate IR plan** — notify the incident commander and open an IR ticket.
2. **Contain the incident** — isolate affected systems, revoke compromised credentials.
3. **Collect forensic evidence** — preserve logs, memory dumps, and network captures (chain of custody).
4. **Eradicate the threat** — patch the vector, remove malware, rotate all secrets.
5. **Document lessons learned** — complete post-incident report within 5 business days.
6. **CIRCIA reporting** — if substantial, notify CISA within 72 hours; ransomware within 24 hours.`,
		Effort:     EffortHours{Junior: 24, Mid: 12, Senior: 6},
		Evidence:   "IR ticket <INC_ID> opened at <TIMESTAMP>. Containment completed at <TIMESTAMP>. Post-incident report at <LINK>.",
		References: []string{id, "IR-4", "IR-6", "IR-8", "ISO 27001 A.5.26"},
		RiskAccept: "If containment cannot be achieved within 4 hours, escalate to CISO and consider emergency change-control for system shutdown.",
	}
}

func tmplContingency(id string) localTemplate {
	return localTemplate{
		Remediation: `### Contingency planning remediation

1. **Test backup restoration** — run a full restore drill in a non-production environment quarterly.
2. **Verify RTO/RPO targets** — ensure recovery time and point objectives are documented and tested.
3. **Update BCP/DRP** — review and sign off the Business Continuity Plan annually.
4. **Automate failover** — configure auto-scaling and multi-AZ deployments for critical services.
5. **Tabletop exercise** — conduct annual scenario-based DR exercise with all stakeholders.`,
		Effort:     EffortHours{Junior: 16, Mid: 8, Senior: 4},
		Evidence:   "Backup restore drill completed <DATE>. RTO achieved: <N> hours (target: <TARGET>). BCP signed off by <NAME> on <DATE>.",
		References: []string{id, "CP-4", "CP-9", "CP-10", "ISO 27001 A.8.13"},
		RiskAccept: "Any RTO/RPO gap must be documented with an interim manual failover procedure and a remediation timeline approved by the system owner.",
	}
}

func tmplSecrets(id string) localTemplate {
	return localTemplate{
		Remediation: `### Secrets management remediation

1. **Revoke the exposed secret immediately** — rotate API keys, tokens, and passwords now.
2. **Scan git history** — run ` + "`vsp scan --mode SECRETS`" + ` across all branches; purge secrets from history with git-filter-repo.
3. **Move to secrets manager** — store all credentials in HashiCorp Vault, AWS Secrets Manager, or equivalent.
4. **Enable pre-commit hooks** — deploy gitleaks or trufflehog as a pre-commit gate.
5. **Audit access logs** — check if the secret was used by unauthorized parties.`,
		Effort:     EffortHours{Junior: 4, Mid: 2, Senior: 1},
		Evidence:   "Secret rotated at <TIMESTAMP>. Git history cleaned in commit <HASH>. Secrets manager migration completed for <N> credentials.",
		References: []string{id, "IA-5", "SC-12", "ISO 27001 A.8.24"},
		RiskAccept: "If rotation cannot be immediate, restrict the secret's scope to minimum required permissions and monitor for anomalous usage.",
	}
}

func tmplSupplyChain(id string) localTemplate {
	return localTemplate{
		Remediation: `### Supply chain security remediation

1. **Generate SBOM** — run ` + "`vsp scan --mode SCA`" + ` to produce a CycloneDX 1.5 SBOM for all components.
2. **Pin dependency versions** — lock all transitive dependencies; enable Dependabot/Renovate auto-PRs.
3. **Verify artifact signatures** — use cosign to verify all container images before deployment.
4. **Audit third-party packages** — review licenses and known vulnerabilities via OSV Scanner.
5. **Establish vendor SLAs** — require SOC 2 Type II or equivalent from critical suppliers.`,
		Effort:     EffortHours{Junior: 12, Mid: 6, Senior: 3},
		Evidence:   "SBOM generated for run <RUN_ID>. All images verified with cosign at <DATE>. Vendor assessments completed for <N> suppliers.",
		References: []string{id, "SR-3", "SR-4", "SA-12", "ISO 27001 A.5.19"},
		RiskAccept: "Unverified third-party components must be isolated in a sandbox environment until verification is complete.",
	}
}

func tmplPhysical(id string) localTemplate {
	return localTemplate{
		Remediation: `### Physical & environmental security

1. **Audit physical access logs** — review badge entry records for the past 90 days.
2. **Enable CCTV coverage** — ensure all server rooms and data center entry points are monitored.
3. **Implement clean-desk policy** — no sensitive data left unattended; enforce screen lock after 5 minutes.
4. **Secure media disposal** — use NIST 800-88 compliant wiping or physical destruction.
5. **Environmental controls** — verify UPS, fire suppression, and temperature monitoring are operational.`,
		Effort:     EffortHours{Junior: 8, Mid: 4, Senior: 2},
		Evidence:   "Physical access audit completed <DATE>. CCTV coverage verified at <LOCATION>. Media disposal log at <LINK>.",
		References: []string{id, "PE-2", "PE-6", "PE-17", "ISO 27001 A.7.1"},
		RiskAccept: "Any physical security gap must be escalated to the facilities team with a remediation timeline not exceeding 30 days.",
	}
}
