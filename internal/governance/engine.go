package governance

import (
	"fmt"
	"time"

	"github.com/vsp/platform/internal/store"
)

// BuildRiskRegister derives risk items from findings.
func BuildRiskRegister(tenantID string, findings []store.Finding) []RiskItem {
	items := make([]RiskItem, 0, len(findings))
	for _, f := range findings {
		if f.Severity == "INFO" || f.Severity == "TRACE" {
			continue
		}
		items = append(items, RiskItem{
			ID:          "risk-" + f.ID,
			TenantID:    tenantID,
			Title:       fmt.Sprintf("[%s] %s", f.Severity, f.RuleID),
			Description: f.Message,
			Level:       severityToRisk(f.Severity),
			Status:      "open",
			Owner:       "security-team",
			FindingID:   f.ID,
			DueDate:     dueDateBySev(f.Severity),
			CreatedAt:   f.CreatedAt,
			UpdatedAt:   f.CreatedAt,
		})
	}
	return items
}

// BuildTraceability maps findings to security controls.
func BuildTraceability(findings []store.Finding) []TraceabilityRow {
	rows := make([]TraceabilityRow, 0)
	for _, f := range findings {
		control, framework := cweToControl(f.CWE)
		rows = append(rows, TraceabilityRow{
			FindingID: f.ID,
			Severity:  f.Severity,
			RuleID:    f.RuleID,
			Control:   control,
			Framework: framework,
			Status:    riskStatus(f.Severity),
		})
	}
	return rows
}

// BuildFrameworkScorecard computes scores per framework from findings.
func BuildFrameworkScorecard(findings []store.Finding) []FrameworkScore {
	// Simplified scoring: start at 100, deduct per finding by severity
	frameworks := map[string]*FrameworkScore{
		"NIST SP 800-53": {Framework: "NIST SP 800-53", Score: 100,
			Domains: []DomainScore{
				{Name: "Access Control (AC)",       Score: 100, Items: 10},
				{Name: "System Integrity (SI)",      Score: 100, Items: 8},
				{Name: "Identification & Auth (IA)", Score: 100, Items: 6},
				{Name: "Audit & Accountability (AU)",Score: 100, Items: 5},
				{Name: "Config Management (CM)",     Score: 100, Items: 7},
			},
		},
		"ISO 27001": {Framework: "ISO 27001", Score: 100,
			Domains: []DomainScore{
				{Name: "A.9 Access Control",          Score: 100, Items: 8},
				{Name: "A.12 Operations Security",    Score: 100, Items: 10},
				{Name: "A.14 System Development",     Score: 100, Items: 9},
				{Name: "A.16 Incident Management",    Score: 100, Items: 4},
				{Name: "A.18 Compliance",             Score: 100, Items: 6},
			},
		},
		"SOC 2 Type II": {Framework: "SOC 2 Type II", Score: 100,
			Domains: []DomainScore{
				{Name: "CC6 Logical Access",          Score: 100, Items: 7},
				{Name: "CC7 System Operations",       Score: 100, Items: 8},
				{Name: "CC8 Change Management",       Score: 100, Items: 5},
				{Name: "A1 Availability",             Score: 100, Items: 4},
				{Name: "PI1 Processing Integrity",    Score: 100, Items: 6},
			},
		},
	}

	for _, f := range findings {
		penalty := map[string]int{"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 1}[f.Severity]
		for _, fw := range frameworks {
			fw.Score = max0(fw.Score - penalty/len(frameworks))
			for i := range fw.Domains {
				if fw.Domains[i].Score > 0 {
					fw.Domains[i].Score = max0(fw.Domains[i].Score - penalty)
					break // affect one domain per finding
				}
			}
		}
	}

	result := make([]FrameworkScore, 0, len(frameworks))
	for _, fw := range frameworks {
		result = append(result, *fw)
	}
	return result
}

// BuildZeroTrust computes DoD Zero Trust 7 pillars scores.
func BuildZeroTrust(findings []store.Finding) []ZeroTrustPillar {
	pillars := []ZeroTrustPillar{
		{Pillar: "User", Score: 95, Level: "Advanced",
			Controls: []string{"MFA", "RBAC", "Session management"}},
		{Pillar: "Device", Score: 80, Level: "Advanced",
			Controls: []string{"Endpoint detection", "Device compliance"}},
		{Pillar: "Network", Score: 85, Level: "Advanced",
			Controls: []string{"Micro-segmentation", "Encrypted transport"}},
		{Pillar: "Application & Workload", Score: 0, Level: "Traditional",
			Controls: []string{"SAST", "DAST", "SCA", "Secrets scanning"}},
		{Pillar: "Data", Score: 75, Level: "Advanced",
			Controls: []string{"Encryption at rest", "DLP", "Classification"}},
		{Pillar: "Visibility & Analytics", Score: 90, Level: "Optimal",
			Controls: []string{"SIEM", "Audit log", "Prometheus metrics"}},
		{Pillar: "Automation & Orchestration", Score: 88, Level: "Advanced",
			Controls: []string{"CI/CD gates", "Policy as code", "Auto-remediation"}},
	}

	// Application pillar score derived from findings
	appScore := 100
	for _, f := range findings {
		appScore -= map[string]int{"CRITICAL": 20, "HIGH": 10, "MEDIUM": 4, "LOW": 1}[f.Severity]
		pillars[3].Findings++
	}
	pillars[3].Score = max0(appScore)
	pillars[3].Level = func() string {
		if appScore >= 80 { return "Advanced" }
		if appScore >= 50 { return "Traditional" }
		return "Traditional"
	}()
	return pillars
}

// BuildSecurityRoadmap generates a maturity roadmap.
func BuildSecurityRoadmap(findings []store.Finding, posture string) []RoadmapItem {
	items := []RoadmapItem{
		{Quarter: "Q2 2026", Title: "Automated SAST in CI/CD pipeline", Priority: "HIGH", Status: "in-progress", Category: "DevSecOps"},
		{Quarter: "Q2 2026", Title: "Secret rotation enforcement", Priority: "HIGH", Status: "planned", Category: "Secrets"},
		{Quarter: "Q2 2026", Title: "Dependency vulnerability SLA", Priority: "MEDIUM", Status: "planned", Category: "SCA"},
		{Quarter: "Q3 2026", Title: "IaC security scanning", Priority: "MEDIUM", Status: "planned", Category: "IaC"},
		{Quarter: "Q3 2026", Title: "SIEM integration (Splunk/Datadog)", Priority: "HIGH", Status: "done", Category: "SIEM"},
		{Quarter: "Q3 2026", Title: "OSCAL AR/POA&M automation", Priority: "MEDIUM", Status: "done", Category: "Compliance"},
		{Quarter: "Q4 2026", Title: "Zero Trust application pillar", Priority: "HIGH", Status: "planned", Category: "ZeroTrust"},
		{Quarter: "Q4 2026", Title: "SOC 2 Type II audit readiness", Priority: "HIGH", Status: "planned", Category: "Compliance"},
		{Quarter: "Q1 2027", Title: "ISO 27001 certification", Priority: "MEDIUM", Status: "planned", Category: "Compliance"},
		{Quarter: "Q1 2027", Title: "ML-based anomaly detection", Priority: "LOW", Status: "planned", Category: "AI/ML"},
	}
	// Add finding-driven items
	if posture == "D" || posture == "F" {
		items = append([]RoadmapItem{
			{Quarter: "Q2 2026", Title: "CRITICAL finding remediation sprint", Priority: "CRITICAL", Status: "overdue", Category: "Remediation"},
		}, items...)
	}
	return items
}

// BuildRACI generates governance chain.
func BuildRACI() []map[string]string {
	return []map[string]string{
		{"activity": "Security scanning", "responsible": "DevSecOps", "accountable": "CISO", "consulted": "Dev Lead", "informed": "CTO"},
		{"activity": "Vulnerability triage", "responsible": "Security Analyst", "accountable": "Security Manager", "consulted": "Dev Lead", "informed": "CISO"},
		{"activity": "Policy management", "responsible": "Security Architect", "accountable": "CISO", "consulted": "Legal", "informed": "Board"},
		{"activity": "Incident response", "responsible": "SOC Analyst", "accountable": "CISO", "consulted": "Legal/PR", "informed": "CEO"},
		{"activity": "Compliance audit", "responsible": "GRC Team", "accountable": "CISO", "consulted": "External Auditor", "informed": "Board"},
		{"activity": "Risk acceptance", "responsible": "Risk Manager", "accountable": "CRO", "consulted": "CISO", "informed": "Board"},
		{"activity": "Penetration testing", "responsible": "Red Team", "accountable": "CISO", "consulted": "Dev Lead", "informed": "CTO"},
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func severityToRisk(sev string) RiskLevel {
	switch sev {
	case "CRITICAL": return RiskCritical
	case "HIGH":     return RiskHigh
	case "MEDIUM":   return RiskMedium
	default:         return RiskLow
	}
}

func dueDateBySev(sev string) time.Time {
	days := map[string]int{"CRITICAL": 3, "HIGH": 14, "MEDIUM": 30, "LOW": 90}[sev]
	return time.Now().AddDate(0, 0, days)
}

func riskStatus(sev string) string {
	if sev == "LOW" { return "monitor" }
	return "open"
}

func cweToControl(cwe string) (control, framework string) {
	m := map[string][2]string{
		"CWE-78":  {"SI-10", "NIST SP 800-53"},
		"CWE-79":  {"SI-10", "NIST SP 800-53"},
		"CWE-89":  {"SI-10", "NIST SP 800-53"},
		"CWE-259": {"IA-5",  "NIST SP 800-53"},
		"CWE-327": {"SC-13", "NIST SP 800-53"},
		"CWE-502": {"SI-10", "NIST SP 800-53"},
		"CWE-798": {"IA-5",  "NIST SP 800-53"},
	}
	if v, ok := m[cwe]; ok {
		return v[0], v[1]
	}
	return "SI-3", "NIST SP 800-53"
}

func max0(n int) int {
	if n < 0 { return 0 }
	return n
}
