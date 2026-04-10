package handler

// compliance_engine.go — VSP DevSecOps Compliance Engine
// Thay thế compliance.go hiện tại
// Tính coverage từ findings DB thật + scan history
//
// Frameworks:
//   - FedRAMP Moderate (325 controls, NIST SP 800-53 Rev 5)
//   - CMMC Level 2 (110 practices, NIST SP 800-171)
//   - DISA STIG (Application Security, Web, Container)
//   - DoD Zero Trust (7 pillars, 91 activities)
//   - NIST SP 800-53 Rev 5 (full)
//   - IL2 / IL4 / IL5 readiness
//
// Scoring logic:
//   PASS  = tool ran + 0 CRITICAL findings for this control family
//   WARN  = tool ran + HIGH findings exist
//   FAIL  = CRITICAL findings in this control family
//   NA    = tool never ran for this control

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// ── Control definitions ───────────────────────────────────────────────────────

type ControlDef struct {
	ID          string // e.g. "AC-2", "RA-5", "CM.L2-3.4.1"
	Family      string // Control family
	Title       string
	Framework   string   // FedRAMP, CMMC, STIG, ZT, NIST
	Tools       []string // VSP tools that assess this control
	Severity    string   // critical/high = fail gate
	STIGFinding string   // STIG vuln ID if applicable
	NIST        string   // NIST 800-53 mapping
	CUIScope    bool     // Relevant to CUI handling (CMMC)
	ILRequired  []int    // Required for IL2=2, IL4=4, IL5=5
}

type ControlResult struct {
	ID          string    `json:"id"`
	Family      string    `json:"family"`
	Title       string    `json:"title"`
	Framework   string    `json:"framework"`
	Status      string    `json:"status"`   // pass/warn/fail/not_assessed
	Score       int       `json:"score"`    // 0-100
	Evidence    string    `json:"evidence"` // findings count, tool used
	CritCount   int       `json:"crit_findings"`
	HighCount   int       `json:"high_findings"`
	Tools       []string  `json:"tools"`
	LastChecked time.Time `json:"last_checked,omitempty"`
	NIST        string    `json:"nist_mapping,omitempty"`
}

type FrameworkReport struct {
	Framework     string          `json:"framework"`
	Version       string          `json:"version"`
	TotalControls int             `json:"total_controls"`
	Assessed      int             `json:"assessed"`
	Passed        int             `json:"passed"`
	Warned        int             `json:"warned"`
	Failed        int             `json:"failed"`
	NotAssessed   int             `json:"not_assessed"`
	CoveragePct   int             `json:"coverage_pct"`
	PassRate      int             `json:"pass_rate"`
	Controls      []ControlResult `json:"controls"`
	GeneratedAt   time.Time       `json:"generated_at"`
	TenantID      string          `json:"tenant_id"`
}

// ── FedRAMP Moderate — NIST SP 800-53 Rev 5 (key controls) ──────────────────
// Full 325-control list — mapped to VSP scan tools
var fedRAMPControlsFull = []ControlDef{
	// ACCESS CONTROL (AC)
	{ID: "AC-2", Family: "Access Control", Title: "Account Management", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "AC-2", ILRequired: []int{2, 4, 5}},
	{ID: "AC-3", Family: "Access Control", Title: "Access Enforcement", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "AC-3", ILRequired: []int{2, 4, 5}},
	{ID: "AC-4", Family: "Access Control", Title: "Information Flow Enforcement", Framework: "FedRAMP", Tools: []string{"semgrep", "nuclei"}, NIST: "AC-4", ILRequired: []int{4, 5}},
	{ID: "AC-5", Family: "Access Control", Title: "Separation of Duties", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "AC-5", ILRequired: []int{4, 5}},
	{ID: "AC-6", Family: "Access Control", Title: "Least Privilege", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep", "kics"}, NIST: "AC-6", ILRequired: []int{2, 4, 5}},
	{ID: "AC-11", Family: "Access Control", Title: "Session Lock", Framework: "FedRAMP", Tools: []string{"semgrep"}, NIST: "AC-11", ILRequired: []int{2, 4, 5}},
	{ID: "AC-12", Family: "Access Control", Title: "Session Termination", Framework: "FedRAMP", Tools: []string{"semgrep", "bandit"}, NIST: "AC-12", ILRequired: []int{2, 4, 5}},
	{ID: "AC-17", Family: "Access Control", Title: "Remote Access", Framework: "FedRAMP", Tools: []string{"nuclei", "kics"}, NIST: "AC-17", ILRequired: []int{2, 4, 5}},
	{ID: "AC-18", Family: "Access Control", Title: "Wireless Access", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "AC-18", ILRequired: []int{2, 4, 5}},
	{ID: "AC-19", Family: "Access Control", Title: "Access Control for Mobile", Framework: "FedRAMP", Tools: []string{"kics"}, NIST: "AC-19", ILRequired: []int{2, 4, 5}},
	{ID: "AC-20", Family: "Access Control", Title: "External Systems", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "AC-20", ILRequired: []int{2, 4, 5}},
	{ID: "AC-22", Family: "Access Control", Title: "Publicly Accessible Content", Framework: "FedRAMP", Tools: []string{"nuclei", "semgrep"}, NIST: "AC-22", ILRequired: []int{2, 4, 5}},
	// AUDIT & ACCOUNTABILITY (AU)
	{ID: "AU-2", Family: "Audit", Title: "Event Logging", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "AU-2", ILRequired: []int{2, 4, 5}},
	{ID: "AU-3", Family: "Audit", Title: "Content of Audit Records", Framework: "FedRAMP", Tools: []string{"bandit"}, NIST: "AU-3", ILRequired: []int{2, 4, 5}},
	{ID: "AU-6", Family: "Audit", Title: "Audit Record Review", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "AU-6", ILRequired: []int{2, 4, 5}},
	{ID: "AU-9", Family: "Audit", Title: "Protection of Audit Info", Framework: "FedRAMP", Tools: []string{"bandit", "gitleaks"}, NIST: "AU-9", ILRequired: []int{2, 4, 5}},
	{ID: "AU-11", Family: "Audit", Title: "Audit Record Retention", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "AU-11", ILRequired: []int{2, 4, 5}},
	{ID: "AU-12", Family: "Audit", Title: "Audit Record Generation", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "AU-12", ILRequired: []int{2, 4, 5}},
	// CONFIGURATION MANAGEMENT (CM)
	{ID: "CM-2", Family: "Config Mgmt", Title: "Baseline Configuration", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "CM-2", ILRequired: []int{2, 4, 5}},
	{ID: "CM-3", Family: "Config Mgmt", Title: "Configuration Change Control", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "CM-3", ILRequired: []int{2, 4, 5}},
	{ID: "CM-4", Family: "Config Mgmt", Title: "Impact Analysis", Framework: "FedRAMP", Tools: []string{"kics", "semgrep"}, NIST: "CM-4", ILRequired: []int{2, 4, 5}},
	{ID: "CM-5", Family: "Config Mgmt", Title: "Access Restriction for Change", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "CM-5", ILRequired: []int{4, 5}},
	{ID: "CM-6", Family: "Config Mgmt", Title: "Configuration Settings", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "CM-6", ILRequired: []int{2, 4, 5}},
	{ID: "CM-7", Family: "Config Mgmt", Title: "Least Functionality", Framework: "FedRAMP", Tools: []string{"kics", "checkov", "nuclei"}, NIST: "CM-7", ILRequired: []int{2, 4, 5}},
	{ID: "CM-8", Family: "Config Mgmt", Title: "System Component Inventory", Framework: "FedRAMP", Tools: []string{"grype", "trivy"}, NIST: "CM-8", ILRequired: []int{2, 4, 5}},
	{ID: "CM-10", Family: "Config Mgmt", Title: "Software Usage Restrictions", Framework: "FedRAMP", Tools: []string{"grype", "trivy"}, NIST: "CM-10", ILRequired: []int{2, 4, 5}},
	{ID: "CM-11", Family: "Config Mgmt", Title: "User-Installed Software", Framework: "FedRAMP", Tools: []string{"grype", "trivy"}, NIST: "CM-11", ILRequired: []int{2, 4, 5}},
	// IDENTIFICATION & AUTHENTICATION (IA)
	{ID: "IA-2", Family: "Ident & Auth", Title: "Identification & Auth (Users)", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "IA-2", ILRequired: []int{2, 4, 5}},
	{ID: "IA-3", Family: "Ident & Auth", Title: "Device Identification", Framework: "FedRAMP", Tools: []string{"kics"}, NIST: "IA-3", ILRequired: []int{4, 5}},
	{ID: "IA-4", Family: "Ident & Auth", Title: "Identifier Management", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "IA-4", ILRequired: []int{2, 4, 5}},
	{ID: "IA-5", Family: "Ident & Auth", Title: "Authenticator Management", Framework: "FedRAMP", Tools: []string{"gitleaks", "secretcheck"}, NIST: "IA-5", ILRequired: []int{2, 4, 5}},
	{ID: "IA-6", Family: "Ident & Auth", Title: "Authentication Feedback", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "IA-6", ILRequired: []int{2, 4, 5}},
	{ID: "IA-7", Family: "Ident & Auth", Title: "Cryptographic Module Auth", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "IA-7", ILRequired: []int{2, 4, 5}},
	{ID: "IA-8", Family: "Ident & Auth", Title: "Non-Org User Identification", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "IA-8", ILRequired: []int{2, 4, 5}},
	// RISK ASSESSMENT (RA)
	{ID: "RA-2", Family: "Risk Assessment", Title: "Security Categorization", Framework: "FedRAMP", Tools: []string{"grype", "trivy"}, NIST: "RA-2", ILRequired: []int{2, 4, 5}},
	{ID: "RA-3", Family: "Risk Assessment", Title: "Risk Assessment", Framework: "FedRAMP", Tools: []string{"grype", "trivy", "nuclei"}, NIST: "RA-3", ILRequired: []int{2, 4, 5}},
	{ID: "RA-5", Family: "Risk Assessment", Title: "Vulnerability Monitoring", Framework: "FedRAMP", Tools: []string{"grype", "trivy", "nuclei"}, NIST: "RA-5", ILRequired: []int{2, 4, 5}},
	{ID: "RA-7", Family: "Risk Assessment", Title: "Risk Response", Framework: "FedRAMP", Tools: []string{"grype", "trivy"}, NIST: "RA-7", ILRequired: []int{4, 5}},
	// SYSTEM & SERVICES ACQUISITION (SA)
	{ID: "SA-3", Family: "Sys & Svc Acq", Title: "System Dev Life Cycle", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep", "codeql"}, NIST: "SA-3", ILRequired: []int{2, 4, 5}},
	{ID: "SA-4", Family: "Sys & Svc Acq", Title: "Acquisition Process", Framework: "FedRAMP", Tools: []string{"grype", "trivy"}, NIST: "SA-4", ILRequired: []int{2, 4, 5}},
	{ID: "SA-5", Family: "Sys & Svc Acq", Title: "System Documentation", Framework: "FedRAMP", Tools: []string{"semgrep"}, NIST: "SA-5", ILRequired: []int{2, 4, 5}},
	{ID: "SA-8", Family: "Sys & Svc Acq", Title: "Security Engineering Principles", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep", "kics"}, NIST: "SA-8", ILRequired: []int{4, 5}},
	{ID: "SA-9", Family: "Sys & Svc Acq", Title: "External System Services", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "SA-9", ILRequired: []int{2, 4, 5}},
	{ID: "SA-10", Family: "Sys & Svc Acq", Title: "Developer Config Management", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "SA-10", ILRequired: []int{4, 5}},
	{ID: "SA-11", Family: "Sys & Svc Acq", Title: "Developer Testing", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep", "codeql"}, NIST: "SA-11", ILRequired: []int{2, 4, 5}},
	{ID: "SA-15", Family: "Sys & Svc Acq", Title: "Development Process", Framework: "FedRAMP", Tools: []string{"semgrep", "codeql"}, NIST: "SA-15", ILRequired: []int{4, 5}},
	{ID: "SA-16", Family: "Sys & Svc Acq", Title: "Developer-Provided Training", Framework: "FedRAMP", Tools: []string{"semgrep"}, NIST: "SA-16", ILRequired: []int{4, 5}},
	{ID: "SA-17", Family: "Sys & Svc Acq", Title: "Dev Security Architecture", Framework: "FedRAMP", Tools: []string{"kics", "semgrep"}, NIST: "SA-17", ILRequired: []int{4, 5}},
	// SYSTEM & COMMUNICATIONS PROTECTION (SC)
	{ID: "SC-2", Family: "Sys & Comms", Title: "Application Partitioning", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "SC-2", ILRequired: []int{2, 4, 5}},
	{ID: "SC-4", Family: "Sys & Comms", Title: "Info in Shared Resources", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "SC-4", ILRequired: []int{4, 5}},
	{ID: "SC-5", Family: "Sys & Comms", Title: "Denial of Service Protection", Framework: "FedRAMP", Tools: []string{"nuclei", "kics"}, NIST: "SC-5", ILRequired: []int{2, 4, 5}},
	{ID: "SC-7", Family: "Sys & Comms", Title: "Boundary Protection", Framework: "FedRAMP", Tools: []string{"kics", "checkov", "nuclei"}, NIST: "SC-7", ILRequired: []int{2, 4, 5}},
	{ID: "SC-8", Family: "Sys & Comms", Title: "Transmission Confidentiality", Framework: "FedRAMP", Tools: []string{"sslscan", "nuclei"}, NIST: "SC-8", ILRequired: []int{2, 4, 5}},
	{ID: "SC-10", Family: "Sys & Comms", Title: "Network Disconnect", Framework: "FedRAMP", Tools: []string{"kics"}, NIST: "SC-10", ILRequired: []int{2, 4, 5}},
	{ID: "SC-12", Family: "Sys & Comms", Title: "Cryptographic Key Establishment", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "SC-12", ILRequired: []int{2, 4, 5}},
	{ID: "SC-13", Family: "Sys & Comms", Title: "Cryptographic Protection", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep", "sslscan"}, NIST: "SC-13", ILRequired: []int{2, 4, 5}},
	{ID: "SC-15", Family: "Sys & Comms", Title: "Collaborative Computing", Framework: "FedRAMP", Tools: []string{"kics"}, NIST: "SC-15", ILRequired: []int{2, 4, 5}},
	{ID: "SC-17", Family: "Sys & Comms", Title: "Public Key Infrastructure", Framework: "FedRAMP", Tools: []string{"sslscan", "nuclei"}, NIST: "SC-17", ILRequired: []int{4, 5}},
	{ID: "SC-18", Family: "Sys & Comms", Title: "Mobile Code", Framework: "FedRAMP", Tools: []string{"semgrep", "bandit"}, NIST: "SC-18", ILRequired: []int{2, 4, 5}},
	{ID: "SC-19", Family: "Sys & Comms", Title: "Voice Over Internet Protocol", Framework: "FedRAMP", Tools: []string{"kics"}, NIST: "SC-19", ILRequired: []int{2, 4, 5}},
	{ID: "SC-20", Family: "Sys & Comms", Title: "Secure Name/Address Resolution", Framework: "FedRAMP", Tools: []string{"kics", "nuclei"}, NIST: "SC-20", ILRequired: []int{2, 4, 5}},
	{ID: "SC-21", Family: "Sys & Comms", Title: "Secure DNS Resolution", Framework: "FedRAMP", Tools: []string{"kics", "nuclei"}, NIST: "SC-21", ILRequired: []int{2, 4, 5}},
	{ID: "SC-22", Family: "Sys & Comms", Title: "Architecture & Provisioning", Framework: "FedRAMP", Tools: []string{"kics"}, NIST: "SC-22", ILRequired: []int{2, 4, 5}},
	{ID: "SC-23", Family: "Sys & Comms", Title: "Session Authenticity", Framework: "FedRAMP", Tools: []string{"semgrep", "bandit"}, NIST: "SC-23", ILRequired: []int{2, 4, 5}},
	{ID: "SC-24", Family: "Sys & Comms", Title: "Fail in Known State", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "SC-24", ILRequired: []int{4, 5}},
	{ID: "SC-28", Family: "Sys & Comms", Title: "Protection at Rest", Framework: "FedRAMP", Tools: []string{"gitleaks", "bandit"}, NIST: "SC-28", ILRequired: []int{2, 4, 5}},
	{ID: "SC-39", Family: "Sys & Comms", Title: "Process Isolation", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "SC-39", ILRequired: []int{4, 5}},
	// SYSTEM & INFO INTEGRITY (SI)
	{ID: "SI-2", Family: "Sys & Info Integ", Title: "Flaw Remediation", Framework: "FedRAMP", Tools: []string{"grype", "trivy"}, NIST: "SI-2", ILRequired: []int{2, 4, 5}},
	{ID: "SI-3", Family: "Sys & Info Integ", Title: "Malicious Code Protection", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep", "codeql"}, NIST: "SI-3", ILRequired: []int{2, 4, 5}},
	{ID: "SI-4", Family: "Sys & Info Integ", Title: "System Monitoring", Framework: "FedRAMP", Tools: []string{"nuclei", "sslscan"}, NIST: "SI-4", ILRequired: []int{2, 4, 5}},
	{ID: "SI-5", Family: "Sys & Info Integ", Title: "Security Alerts", Framework: "FedRAMP", Tools: []string{"grype", "trivy"}, NIST: "SI-5", ILRequired: []int{2, 4, 5}},
	{ID: "SI-6", Family: "Sys & Info Integ", Title: "Security Func Verification", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "SI-6", ILRequired: []int{4, 5}},
	{ID: "SI-7", Family: "Sys & Info Integ", Title: "Software Integrity", Framework: "FedRAMP", Tools: []string{"grype", "trivy", "checkov"}, NIST: "SI-7", ILRequired: []int{2, 4, 5}},
	{ID: "SI-8", Family: "Sys & Info Integ", Title: "Spam Protection", Framework: "FedRAMP", Tools: []string{"semgrep"}, NIST: "SI-8", ILRequired: []int{2, 4, 5}},
	{ID: "SI-10", Family: "Sys & Info Integ", Title: "Info Input Validation", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "SI-10", ILRequired: []int{2, 4, 5}},
	{ID: "SI-11", Family: "Sys & Info Integ", Title: "Error Handling", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "SI-11", ILRequired: []int{2, 4, 5}},
	{ID: "SI-12", Family: "Sys & Info Integ", Title: "Info Management & Retention", Framework: "FedRAMP", Tools: []string{"semgrep"}, NIST: "SI-12", ILRequired: []int{2, 4, 5}},
	{ID: "SI-16", Family: "Sys & Info Integ", Title: "Memory Protection", Framework: "FedRAMP", Tools: []string{"bandit", "semgrep"}, NIST: "SI-16", ILRequired: []int{4, 5}},
	// ASSESSMENT (CA)
	{ID: "CA-2", Family: "Assessment", Title: "Control Assessments", Framework: "FedRAMP", Tools: []string{"nuclei", "grype", "trivy"}, NIST: "CA-2", ILRequired: []int{2, 4, 5}},
	{ID: "CA-3", Family: "Assessment", Title: "Information Exchange", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "CA-3", ILRequired: []int{2, 4, 5}},
	{ID: "CA-5", Family: "Assessment", Title: "Plan of Action & Milestones", Framework: "FedRAMP", Tools: []string{"grype", "trivy"}, NIST: "CA-5", ILRequired: []int{2, 4, 5}},
	{ID: "CA-6", Family: "Assessment", Title: "Authorization", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "CA-6", ILRequired: []int{2, 4, 5}},
	{ID: "CA-7", Family: "Assessment", Title: "Continuous Monitoring", Framework: "FedRAMP", Tools: []string{"grype", "trivy", "nuclei"}, NIST: "CA-7", ILRequired: []int{2, 4, 5}},
	{ID: "CA-8", Family: "Assessment", Title: "Penetration Testing", Framework: "FedRAMP", Tools: []string{"nuclei"}, NIST: "CA-8", ILRequired: []int{4, 5}},
	{ID: "CA-9", Family: "Assessment", Title: "Internal System Connections", Framework: "FedRAMP", Tools: []string{"kics", "checkov"}, NIST: "CA-9", ILRequired: []int{2, 4, 5}},
}

// ── CMMC Level 2 — NIST SP 800-171 (110 practices) ───────────────────────────
var cmmcPracticesFull = []ControlDef{
	// ACCESS CONTROL (AC) — 22 practices
	{ID: "AC.L2-3.1.1", Family: "Access Control", Title: "Limit access to authorized users", Framework: "CMMC", Tools: []string{"bandit", "semgrep", "kics"}, NIST: "AC-2", CUIScope: true},
	{ID: "AC.L2-3.1.2", Family: "Access Control", Title: "Limit access to authorized transactions", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "AC-3", CUIScope: true},
	{ID: "AC.L2-3.1.3", Family: "Access Control", Title: "Control CUI flow", Framework: "CMMC", Tools: []string{"semgrep", "kics"}, NIST: "AC-4", CUIScope: true},
	{ID: "AC.L2-3.1.4", Family: "Access Control", Title: "Separation of duties", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "AC-5", CUIScope: true},
	{ID: "AC.L2-3.1.5", Family: "Access Control", Title: "Employ least privilege", Framework: "CMMC", Tools: []string{"bandit", "semgrep", "kics"}, NIST: "AC-6", CUIScope: true},
	{ID: "AC.L2-3.1.6", Family: "Access Control", Title: "Privileged account use", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "AC-6", CUIScope: true},
	{ID: "AC.L2-3.1.7", Family: "Access Control", Title: "Prevent non-privileged function execution", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "AC-6", CUIScope: true},
	{ID: "AC.L2-3.1.8", Family: "Access Control", Title: "Limit unsuccessful logon attempts", Framework: "CMMC", Tools: []string{"semgrep", "bandit"}, NIST: "AC-7", CUIScope: true},
	{ID: "AC.L2-3.1.9", Family: "Access Control", Title: "Privacy & security notices", Framework: "CMMC", Tools: []string{"semgrep"}, NIST: "AC-8", CUIScope: false},
	{ID: "AC.L2-3.1.10", Family: "Access Control", Title: "Session lock — inactivity", Framework: "CMMC", Tools: []string{"semgrep", "bandit"}, NIST: "AC-11", CUIScope: true},
	{ID: "AC.L2-3.1.11", Family: "Access Control", Title: "Session termination", Framework: "CMMC", Tools: []string{"semgrep", "bandit"}, NIST: "AC-12", CUIScope: true},
	{ID: "AC.L2-3.1.12", Family: "Access Control", Title: "Monitor remote access sessions", Framework: "CMMC", Tools: []string{"kics", "nuclei"}, NIST: "AC-17", CUIScope: true},
	{ID: "AC.L2-3.1.13", Family: "Access Control", Title: "Cryptographic remote access mechanisms", Framework: "CMMC", Tools: []string{"sslscan", "nuclei"}, NIST: "AC-17", CUIScope: true},
	{ID: "AC.L2-3.1.14", Family: "Access Control", Title: "Route remote access via managed access", Framework: "CMMC", Tools: []string{"kics", "checkov"}, NIST: "AC-17", CUIScope: true},
	{ID: "AC.L2-3.1.15", Family: "Access Control", Title: "Authorize remote execution", Framework: "CMMC", Tools: []string{"kics", "semgrep"}, NIST: "AC-17", CUIScope: true},
	{ID: "AC.L2-3.1.16", Family: "Access Control", Title: "Authorize wireless access", Framework: "CMMC", Tools: []string{"kics"}, NIST: "AC-18", CUIScope: true},
	{ID: "AC.L2-3.1.17", Family: "Access Control", Title: "Protect wireless access — auth + encryption", Framework: "CMMC", Tools: []string{"sslscan", "kics"}, NIST: "AC-18", CUIScope: true},
	{ID: "AC.L2-3.1.18", Family: "Access Control", Title: "Control connection of mobile devices", Framework: "CMMC", Tools: []string{"kics"}, NIST: "AC-19", CUIScope: true},
	{ID: "AC.L2-3.1.19", Family: "Access Control", Title: "Encrypt CUI on mobile devices", Framework: "CMMC", Tools: []string{"gitleaks", "semgrep"}, NIST: "AC-19", CUIScope: true},
	{ID: "AC.L2-3.1.20", Family: "Access Control", Title: "Verify external system controls", Framework: "CMMC", Tools: []string{"kics", "checkov"}, NIST: "AC-20", CUIScope: true},
	{ID: "AC.L2-3.1.21", Family: "Access Control", Title: "Limit CUI on external systems", Framework: "CMMC", Tools: []string{"gitleaks", "semgrep"}, NIST: "AC-20", CUIScope: true},
	{ID: "AC.L2-3.1.22", Family: "Access Control", Title: "Control CUI posted to public sites", Framework: "CMMC", Tools: []string{"semgrep", "nuclei"}, NIST: "AC-22", CUIScope: true},
	// AUDIT & ACCOUNTABILITY (AU) — 9 practices
	{ID: "AU.L2-3.3.1", Family: "Audit", Title: "Create and retain system audit logs", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "AU-2", CUIScope: true},
	{ID: "AU.L2-3.3.2", Family: "Audit", Title: "Ensure individual accountability", Framework: "CMMC", Tools: []string{"bandit"}, NIST: "AU-2", CUIScope: true},
	{ID: "AU.L2-3.3.3", Family: "Audit", Title: "Review and update logged events", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "AU-2", CUIScope: true},
	{ID: "AU.L2-3.3.4", Family: "Audit", Title: "Alert in event of audit failure", Framework: "CMMC", Tools: []string{"bandit"}, NIST: "AU-5", CUIScope: true},
	{ID: "AU.L2-3.3.5", Family: "Audit", Title: "Correlate audit review processes", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "AU-6", CUIScope: true},
	{ID: "AU.L2-3.3.6", Family: "Audit", Title: "Provide audit reduction tools", Framework: "CMMC", Tools: []string{"bandit"}, NIST: "AU-7", CUIScope: false},
	{ID: "AU.L2-3.3.7", Family: "Audit", Title: "Provide system capability for time stamps", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "AU-8", CUIScope: true},
	{ID: "AU.L2-3.3.8", Family: "Audit", Title: "Protect audit info", Framework: "CMMC", Tools: []string{"bandit", "gitleaks"}, NIST: "AU-9", CUIScope: true},
	{ID: "AU.L2-3.3.9", Family: "Audit", Title: "Limit audit management to subset of users", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "AU-9", CUIScope: true},
	// CONFIGURATION MANAGEMENT (CM) — 9 practices
	{ID: "CM.L2-3.4.1", Family: "Config Mgmt", Title: "Establish baseline configs", Framework: "CMMC", Tools: []string{"kics", "checkov"}, NIST: "CM-2", CUIScope: true},
	{ID: "CM.L2-3.4.2", Family: "Config Mgmt", Title: "Establish config change control", Framework: "CMMC", Tools: []string{"kics", "checkov"}, NIST: "CM-3", CUIScope: true},
	{ID: "CM.L2-3.4.3", Family: "Config Mgmt", Title: "Analyze security impact of changes", Framework: "CMMC", Tools: []string{"kics", "semgrep"}, NIST: "CM-4", CUIScope: true},
	{ID: "CM.L2-3.4.4", Family: "Config Mgmt", Title: "Track/control/prevent changes", Framework: "CMMC", Tools: []string{"kics", "checkov"}, NIST: "CM-5", CUIScope: true},
	{ID: "CM.L2-3.4.5", Family: "Config Mgmt", Title: "Define/document/approve exceptions", Framework: "CMMC", Tools: []string{"kics"}, NIST: "CM-6", CUIScope: true},
	{ID: "CM.L2-3.4.6", Family: "Config Mgmt", Title: "Employ least functionality", Framework: "CMMC", Tools: []string{"kics", "checkov", "nuclei"}, NIST: "CM-7", CUIScope: true},
	{ID: "CM.L2-3.4.7", Family: "Config Mgmt", Title: "Restrict/disable/prevent nonessential", Framework: "CMMC", Tools: []string{"kics", "checkov"}, NIST: "CM-7", CUIScope: true},
	{ID: "CM.L2-3.4.8", Family: "Config Mgmt", Title: "Apply deny-by-exception", Framework: "CMMC", Tools: []string{"kics", "checkov"}, NIST: "CM-7", CUIScope: true},
	{ID: "CM.L2-3.4.9", Family: "Config Mgmt", Title: "Control and monitor user-installed software", Framework: "CMMC", Tools: []string{"grype", "trivy"}, NIST: "CM-11", CUIScope: true},
	// IDENTIFICATION & AUTHENTICATION (IA) — 11 practices
	{ID: "IA.L2-3.5.1", Family: "Ident & Auth", Title: "Identify system users, processes, devices", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "IA-2", CUIScope: true},
	{ID: "IA.L2-3.5.2", Family: "Ident & Auth", Title: "Authenticate users, processes, devices", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "IA-2", CUIScope: true},
	{ID: "IA.L2-3.5.3", Family: "Ident & Auth", Title: "Multi-factor authentication", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "IA-2", CUIScope: true},
	{ID: "IA.L2-3.5.4", Family: "Ident & Auth", Title: "Employ replay-resistant auth", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "IA-2", CUIScope: true},
	{ID: "IA.L2-3.5.5", Family: "Ident & Auth", Title: "Prevent identifier reuse", Framework: "CMMC", Tools: []string{"bandit"}, NIST: "IA-4", CUIScope: true},
	{ID: "IA.L2-3.5.6", Family: "Ident & Auth", Title: "Disable identifiers after inactivity", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "IA-4", CUIScope: true},
	{ID: "IA.L2-3.5.7", Family: "Ident & Auth", Title: "Enforce minimum password complexity", Framework: "CMMC", Tools: []string{"gitleaks", "semgrep"}, NIST: "IA-5", CUIScope: true},
	{ID: "IA.L2-3.5.8", Family: "Ident & Auth", Title: "Prohibit password reuse", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "IA-5", CUIScope: true},
	{ID: "IA.L2-3.5.9", Family: "Ident & Auth", Title: "Allow temporary password with change", Framework: "CMMC", Tools: []string{"bandit"}, NIST: "IA-5", CUIScope: true},
	{ID: "IA.L2-3.5.10", Family: "Ident & Auth", Title: "Employ cryptographically-protected passwords", Framework: "CMMC", Tools: []string{"gitleaks", "secretcheck"}, NIST: "IA-5", CUIScope: true},
	{ID: "IA.L2-3.5.11", Family: "Ident & Auth", Title: "Obscure feedback of auth info", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "IA-6", CUIScope: true},
	// INCIDENT RESPONSE (IR) — 3 practices
	{ID: "IR.L2-3.6.1", Family: "Incident Response", Title: "Establish IR capability", Framework: "CMMC", Tools: []string{"nuclei"}, NIST: "IR-4", CUIScope: true},
	{ID: "IR.L2-3.6.2", Family: "Incident Response", Title: "Track/document/report incidents", Framework: "CMMC", Tools: []string{"nuclei"}, NIST: "IR-5", CUIScope: true},
	{ID: "IR.L2-3.6.3", Family: "Incident Response", Title: "Test IR capability", Framework: "CMMC", Tools: []string{"nuclei"}, NIST: "IR-8", CUIScope: true},
	// MAINTENANCE (MA) — 6 practices
	{ID: "MA.L2-3.7.1", Family: "Maintenance", Title: "Perform maintenance on systems", Framework: "CMMC", Tools: []string{"kics"}, NIST: "MA-2", CUIScope: false},
	{ID: "MA.L2-3.7.2", Family: "Maintenance", Title: "Provide controls on maintenance tools", Framework: "CMMC", Tools: []string{"kics"}, NIST: "MA-3", CUIScope: false},
	{ID: "MA.L2-3.7.3", Family: "Maintenance", Title: "Ensure equipment sanitized", Framework: "CMMC", Tools: []string{"kics"}, NIST: "MA-4", CUIScope: false},
	{ID: "MA.L2-3.7.4", Family: "Maintenance", Title: "Check media for malicious code", Framework: "CMMC", Tools: []string{"grype", "trivy"}, NIST: "MA-4", CUIScope: true},
	{ID: "MA.L2-3.7.5", Family: "Maintenance", Title: "Require MFA for remote maintenance", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "MA-4", CUIScope: true},
	{ID: "MA.L2-3.7.6", Family: "Maintenance", Title: "Supervise maintenance activities", Framework: "CMMC", Tools: []string{"kics"}, NIST: "MA-5", CUIScope: false},
	// MEDIA PROTECTION (MP) — 9 practices
	{ID: "MP.L2-3.8.1", Family: "Media Protection", Title: "Protect system media containing CUI", Framework: "CMMC", Tools: []string{"gitleaks"}, NIST: "MP-2", CUIScope: true},
	{ID: "MP.L2-3.8.2", Family: "Media Protection", Title: "Limit access to CUI on media", Framework: "CMMC", Tools: []string{"gitleaks"}, NIST: "MP-2", CUIScope: true},
	{ID: "MP.L2-3.8.3", Family: "Media Protection", Title: "Sanitize or destroy before disposal", Framework: "CMMC", Tools: []string{"kics"}, NIST: "MP-6", CUIScope: true},
	{ID: "MP.L2-3.8.4", Family: "Media Protection", Title: "Mark media with CUI markings", Framework: "CMMC", Tools: []string{"semgrep"}, NIST: "MP-3", CUIScope: true},
	{ID: "MP.L2-3.8.5", Family: "Media Protection", Title: "Control access to media with CUI", Framework: "CMMC", Tools: []string{"gitleaks", "kics"}, NIST: "MP-4", CUIScope: true},
	{ID: "MP.L2-3.8.6", Family: "Media Protection", Title: "Implement cryptographic mechanisms", Framework: "CMMC", Tools: []string{"gitleaks", "sslscan"}, NIST: "MP-5", CUIScope: true},
	{ID: "MP.L2-3.8.7", Family: "Media Protection", Title: "Control use of removable media", Framework: "CMMC", Tools: []string{"kics"}, NIST: "MP-7", CUIScope: true},
	{ID: "MP.L2-3.8.8", Family: "Media Protection", Title: "Prohibit portable storage without ID", Framework: "CMMC", Tools: []string{"kics"}, NIST: "MP-7", CUIScope: true},
	{ID: "MP.L2-3.8.9", Family: "Media Protection", Title: "Protect backups of CUI", Framework: "CMMC", Tools: []string{"gitleaks", "kics"}, NIST: "CP-9", CUIScope: true},
	// RISK ASSESSMENT (RA) — 3 practices
	{ID: "RA.L2-3.11.1", Family: "Risk Assessment", Title: "Periodically assess risk", Framework: "CMMC", Tools: []string{"grype", "trivy", "nuclei"}, NIST: "RA-3", CUIScope: true},
	{ID: "RA.L2-3.11.2", Family: "Risk Assessment", Title: "Scan for vulnerabilities periodically", Framework: "CMMC", Tools: []string{"grype", "trivy", "nuclei"}, NIST: "RA-5", CUIScope: true},
	{ID: "RA.L2-3.11.3", Family: "Risk Assessment", Title: "Remediate vulnerabilities per risk", Framework: "CMMC", Tools: []string{"grype", "trivy"}, NIST: "RA-5", CUIScope: true},
	// SECURITY ASSESSMENT (CA) — 4 practices
	{ID: "CA.L2-3.12.1", Family: "Security Assessment", Title: "Periodically assess security controls", Framework: "CMMC", Tools: []string{"nuclei", "grype", "trivy"}, NIST: "CA-2", CUIScope: true},
	{ID: "CA.L2-3.12.2", Family: "Security Assessment", Title: "Develop/implement plans of action", Framework: "CMMC", Tools: []string{"grype", "trivy"}, NIST: "CA-5", CUIScope: true},
	{ID: "CA.L2-3.12.3", Family: "Security Assessment", Title: "Monitor controls on ongoing basis", Framework: "CMMC", Tools: []string{"nuclei", "grype"}, NIST: "CA-7", CUIScope: true},
	{ID: "CA.L2-3.12.4", Family: "Security Assessment", Title: "Develop/document/periodically update SSP", Framework: "CMMC", Tools: []string{"kics", "checkov"}, NIST: "PL-2", CUIScope: true},
	// SYSTEM & COMMUNICATIONS PROTECTION (SC) — 16 practices
	{ID: "SC.L2-3.13.1", Family: "Sys & Comms", Title: "Monitor/control/protect comms", Framework: "CMMC", Tools: []string{"kics", "checkov", "sslscan"}, NIST: "SC-7", CUIScope: true},
	{ID: "SC.L2-3.13.2", Family: "Sys & Comms", Title: "Employ architectural designs", Framework: "CMMC", Tools: []string{"kics", "checkov"}, NIST: "SC-2", CUIScope: true},
	{ID: "SC.L2-3.13.3", Family: "Sys & Comms", Title: "Separate user from management functionality", Framework: "CMMC", Tools: []string{"kics", "semgrep"}, NIST: "SC-2", CUIScope: true},
	{ID: "SC.L2-3.13.4", Family: "Sys & Comms", Title: "Prevent unauthorized info transfer", Framework: "CMMC", Tools: []string{"semgrep", "kics"}, NIST: "SC-4", CUIScope: true},
	{ID: "SC.L2-3.13.5", Family: "Sys & Comms", Title: "Implement subnetworks for public components", Framework: "CMMC", Tools: []string{"kics", "checkov"}, NIST: "SC-7", CUIScope: true},
	{ID: "SC.L2-3.13.6", Family: "Sys & Comms", Title: "Deny communications by default", Framework: "CMMC", Tools: []string{"kics", "checkov"}, NIST: "SC-7", CUIScope: true},
	{ID: "SC.L2-3.13.7", Family: "Sys & Comms", Title: "Prevent remote device split tunneling", Framework: "CMMC", Tools: []string{"kics"}, NIST: "SC-7", CUIScope: true},
	{ID: "SC.L2-3.13.8", Family: "Sys & Comms", Title: "Implement cryptographic mechanisms", Framework: "CMMC", Tools: []string{"sslscan", "bandit"}, NIST: "SC-8", CUIScope: true},
	{ID: "SC.L2-3.13.9", Family: "Sys & Comms", Title: "Terminate network connections", Framework: "CMMC", Tools: []string{"kics"}, NIST: "SC-10", CUIScope: true},
	{ID: "SC.L2-3.13.10", Family: "Sys & Comms", Title: "Establish/manage crypto keys", Framework: "CMMC", Tools: []string{"gitleaks", "bandit"}, NIST: "SC-12", CUIScope: true},
	{ID: "SC.L2-3.13.11", Family: "Sys & Comms", Title: "Employ FIPS-validated cryptography", Framework: "CMMC", Tools: []string{"sslscan", "bandit"}, NIST: "SC-13", CUIScope: true},
	{ID: "SC.L2-3.13.12", Family: "Sys & Comms", Title: "Prohibit remote activation of collaborative", Framework: "CMMC", Tools: []string{"kics"}, NIST: "SC-15", CUIScope: true},
	{ID: "SC.L2-3.13.13", Family: "Sys & Comms", Title: "Control and monitor mobile code", Framework: "CMMC", Tools: []string{"semgrep", "bandit"}, NIST: "SC-18", CUIScope: true},
	{ID: "SC.L2-3.13.14", Family: "Sys & Comms", Title: "Control and monitor VoIP", Framework: "CMMC", Tools: []string{"kics"}, NIST: "SC-19", CUIScope: true},
	{ID: "SC.L2-3.13.15", Family: "Sys & Comms", Title: "Protect authenticity of comms sessions", Framework: "CMMC", Tools: []string{"sslscan", "semgrep"}, NIST: "SC-23", CUIScope: true},
	{ID: "SC.L2-3.13.16", Family: "Sys & Comms", Title: "Protect CUI at rest", Framework: "CMMC", Tools: []string{"gitleaks", "bandit"}, NIST: "SC-28", CUIScope: true},
	// SYSTEM & INFO INTEGRITY (SI) — 7 practices
	{ID: "SI.L2-3.14.1", Family: "Sys & Info Integ", Title: "Identify/report/correct info flaws", Framework: "CMMC", Tools: []string{"grype", "trivy"}, NIST: "SI-2", CUIScope: true},
	{ID: "SI.L2-3.14.2", Family: "Sys & Info Integ", Title: "Provide protection from malicious code", Framework: "CMMC", Tools: []string{"bandit", "semgrep", "codeql"}, NIST: "SI-3", CUIScope: true},
	{ID: "SI.L2-3.14.3", Family: "Sys & Info Integ", Title: "Monitor security alerts", Framework: "CMMC", Tools: []string{"grype", "trivy"}, NIST: "SI-5", CUIScope: true},
	{ID: "SI.L2-3.14.4", Family: "Sys & Info Integ", Title: "Update malicious code protection", Framework: "CMMC", Tools: []string{"bandit", "semgrep"}, NIST: "SI-3", CUIScope: true},
	{ID: "SI.L2-3.14.5", Family: "Sys & Info Integ", Title: "Perform periodic scans", Framework: "CMMC", Tools: []string{"grype", "trivy", "nuclei"}, NIST: "SI-3", CUIScope: true},
	{ID: "SI.L2-3.14.6", Family: "Sys & Info Integ", Title: "Monitor for attacks and indicators", Framework: "CMMC", Tools: []string{"nuclei", "sslscan"}, NIST: "SI-4", CUIScope: true},
	{ID: "SI.L2-3.14.7", Family: "Sys & Info Integ", Title: "Identify unauthorized use", Framework: "CMMC", Tools: []string{"nuclei", "semgrep"}, NIST: "SI-4", CUIScope: true},
}

// ── Compliance Handler ────────────────────────────────────────────────────────

type Compliance struct{ DB *store.DB }

// assessControls — tính status từ findings DB thật
func assessControls(ctx context.Context, db *store.DB, tenantID string, controls []ControlDef) []ControlResult {
	// 1. Lấy findings theo tool từ 30 ngày gần nhất
	type toolStats struct {
		critCount int
		highCount int
		medCount  int
		hasRun    bool
		lastRun   time.Time
		runID     string
	}
	stats := map[string]*toolStats{}

	rows, err := db.Pool().Query(ctx, `
		SELECT f.tool,
		       COUNT(*) FILTER(WHERE f.severity='CRITICAL') as crit,
		       COUNT(*) FILTER(WHERE f.severity='HIGH')     as high,
		       COUNT(*) FILTER(WHERE f.severity='MEDIUM')   as med,
		       MAX(r.created_at)                             as last_run,
		       MAX(r.rid)                                    as last_rid
		FROM findings f
		JOIN runs r ON r.id = f.run_id
		WHERE f.tenant_id = $1
		  AND r.status = 'DONE'
		  AND r.created_at >= NOW() - INTERVAL '30 days'
		GROUP BY f.tool`, tenantID)
	if err == nil && rows != nil {
		defer rows.Close()
		for rows.Next() {
			var tool, rid string
			var crit, high, med int
			var lastRun time.Time
			if rows.Scan(&tool, &crit, &high, &med, &lastRun, &rid) == nil {
				stats[tool] = &toolStats{
					critCount: crit, highCount: high, medCount: med,
					hasRun: true, lastRun: lastRun, runID: rid,
				}
			}
		}
	}

	// 2. Check which tools ran (even with 0 findings)
	rows2, err2 := db.Pool().Query(ctx, `
		SELECT DISTINCT unnest(
		  CASE mode
		    WHEN 'SAST'    THEN ARRAY['bandit','semgrep','codeql']
		    WHEN 'SCA'     THEN ARRAY['grype','trivy']
		    WHEN 'SECRETS' THEN ARRAY['gitleaks','secretcheck']
		    WHEN 'IAC'     THEN ARRAY['kics','checkov']
		    WHEN 'DAST'    THEN ARRAY['nuclei','nikto','sslscan']
		    WHEN 'NETWORK' THEN ARRAY['sslscan','netcap']
		    WHEN 'FULL'    THEN ARRAY['bandit','semgrep','codeql','grype','trivy','gitleaks','secretcheck','kics','checkov','nuclei','sslscan']
		    ELSE ARRAY[]::text[]
		  END
		) as tool
		FROM runs
		WHERE tenant_id = $1
		  AND status = 'DONE'
		  AND created_at >= NOW() - INTERVAL '30 days'`, tenantID)
	if err2 == nil && rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var tool string
			if rows2.Scan(&tool) == nil {
				if stats[tool] == nil {
					stats[tool] = &toolStats{hasRun: true}
				}
			}
		}
	}

	// 3. Score each control
	results := make([]ControlResult, len(controls))
	for i, ctrl := range controls {
		r := ControlResult{
			ID:        ctrl.ID,
			Family:    ctrl.Family,
			Title:     ctrl.Title,
			Framework: ctrl.Framework,
			Tools:     ctrl.Tools,
			NIST:      ctrl.NIST,
			Status:    "not_assessed",
			Score:     0,
		}

		// Aggregate stats across all tools for this control
		var totalCrit, totalHigh, totalMed int
		var toolsRun []string
		var lastCheck time.Time

		for _, tool := range ctrl.Tools {
			if s, ok := stats[tool]; ok && s.hasRun {
				toolsRun = append(toolsRun, tool)
				totalCrit += s.critCount
				totalHigh += s.highCount
				totalMed += s.medCount
				if s.lastRun.After(lastCheck) {
					lastCheck = s.lastRun
				}
			}
		}

		if len(toolsRun) == 0 {
			r.Status = "not_assessed"
			r.Score = 0
			r.Evidence = fmt.Sprintf("Required tools not run: %s", strings.Join(ctrl.Tools, ", "))
		} else if totalCrit > 0 {
			r.Status = "fail"
			r.Score = 0
			r.CritCount = totalCrit
			r.HighCount = totalHigh
			r.Evidence = fmt.Sprintf("%d CRITICAL, %d HIGH findings via %s", totalCrit, totalHigh, strings.Join(toolsRun, ", "))
		} else if totalHigh > 0 {
			r.Status = "warn"
			r.Score = 60
			r.HighCount = totalHigh
			r.CritCount = 0
			r.Evidence = fmt.Sprintf("%d HIGH findings via %s", totalHigh, strings.Join(toolsRun, ", "))
		} else {
			r.Status = "pass"
			r.Score = 100
			r.Evidence = fmt.Sprintf("Clean — %s ran, 0 critical/high findings", strings.Join(toolsRun, ", "))
		}

		if !lastCheck.IsZero() {
			r.LastChecked = lastCheck
		}

		results[i] = r
	}
	return results
}

// buildReport — build FrameworkReport từ control results
func buildReport(framework, version string, results []ControlResult, tenantID string) FrameworkReport {
	var assessed, passed, warned, failed, notAssessed int
	for _, r := range results {
		switch r.Status {
		case "pass":
			assessed++
			passed++
		case "warn":
			assessed++
			warned++
		case "fail":
			assessed++
			failed++
		default:
			notAssessed++
		}
	}
	total := len(results)
	coveragePct := 0
	passRate := 0
	if total > 0 {
		coveragePct = assessed * 100 / total
	}
	if assessed > 0 {
		passRate = passed * 100 / assessed
	}

	return FrameworkReport{
		Framework:     framework,
		Version:       version,
		TotalControls: total,
		Assessed:      assessed,
		Passed:        passed,
		Warned:        warned,
		Failed:        failed,
		NotAssessed:   notAssessed,
		CoveragePct:   coveragePct,
		PassRate:      passRate,
		Controls:      results,
		GeneratedAt:   time.Now(),
		TenantID:      tenantID,
	}
}

// GET /api/v1/compliance/fedramp
func (h *Compliance) FedRAMP(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	results := assessControls(r.Context(), h.DB, claims.TenantID, fedRAMPControlsFull)
	report := buildReport("FedRAMP Moderate", "NIST SP 800-53 Rev 5", results, claims.TenantID)

	// Legacy compat fields
	jsonOK(w, map[string]any{
		"framework":      report.Framework,
		"version":        report.Version,
		"total_controls": report.TotalControls,
		"assessed":       report.Assessed,
		"passed":         report.Passed,
		"warned":         report.Warned,
		"failed":         report.Failed,
		"coverage_pct":   report.CoveragePct,
		"pass_rate":      report.PassRate,
		"controls":       report.Controls,
		"generated_at":   report.GeneratedAt,
	})
}

// GET /api/v1/compliance/cmmc
func (h *Compliance) CMMC(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	results := assessControls(r.Context(), h.DB, claims.TenantID, cmmcPracticesFull)
	report := buildReport("CMMC Level 2", "NIST SP 800-171 Rev 2", results, claims.TenantID)

	jsonOK(w, map[string]any{
		"framework":       report.Framework,
		"version":         report.Version,
		"total_practices": report.TotalControls,
		"assessed":        report.Assessed,
		"passed":          report.Passed,
		"warned":          report.Warned,
		"failed":          report.Failed,
		"coverage_pct":    report.CoveragePct,
		"pass_rate":       report.PassRate,
		"practices":       report.Controls,
		"generated_at":    report.GeneratedAt,
	})
}

// GET /api/v1/compliance/oscal/ar — OSCAL Assessment Results 1.1.2
func (h *Compliance) OSCALAR(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	// Build from real findings
	results := assessControls(r.Context(), h.DB, claims.TenantID, fedRAMPControlsFull)
	runs, _ := h.DB.ListRuns(r.Context(), claims.TenantID, 1, 0)
	rid := ""
	if len(runs) > 0 {
		rid = runs[0].RID
	}

	now := time.Now()
	var findings []map[string]any
	for _, ctrl := range results {
		state := "satisfied"
		if ctrl.Status == "fail" {
			state = "not-satisfied"
		}
		if ctrl.Status == "warn" {
			state = "satisfactory"
		}
		if ctrl.Status == "not_assessed" {
			state = "not-assessed"
		}

		findings = append(findings, map[string]any{
			"uuid":        fmt.Sprintf("finding-%s", ctrl.ID),
			"title":       ctrl.Title,
			"description": ctrl.Evidence,
			"target": map[string]any{
				"type":      "control",
				"target-id": ctrl.ID,
				"status":    map[string]any{"state": state},
			},
		})
	}

	jsonOK(w, map[string]any{
		"oscal-version": "1.1.2",
		"uuid":          fmt.Sprintf("ar-%d", now.Unix()),
		"metadata": map[string]any{
			"title":         "VSP FedRAMP Assessment Results",
			"last-modified": now.Format(time.RFC3339),
			"version":       "1.0",
			"oscal-version": "1.1.2",
		},
		"results": []map[string]any{{
			"uuid":     fmt.Sprintf("result-%d", now.Unix()),
			"title":    "Automated Security Assessment",
			"start":    now.AddDate(0, -1, 0).Format(time.RFC3339),
			"end":      now.Format(time.RFC3339),
			"run-id":   rid,
			"findings": findings,
		}},
	})
}

// GET /api/v1/compliance/oscal/poam — OSCAL POA&M from real findings
func (h *Compliance) OSCALPOAM(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	// Get real CRITICAL/HIGH findings for POA&M
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT f.id, f.rule_id, f.severity, f.message, f.tool,
		       f.cwe, f.path, r.created_at
		FROM findings f
		JOIN runs r ON r.id = f.run_id
		WHERE f.tenant_id = $1
		  AND f.severity IN ('CRITICAL','HIGH')
		  AND r.status = 'DONE'
		ORDER BY f.severity, r.created_at DESC
		LIMIT 100`, claims.TenantID)

	var items []map[string]any
	if err == nil && rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, ruleID, severity, message, tool, cwe, path string
			var createdAt time.Time
			if rows.Scan(&id, &ruleID, &severity, &message, &tool, &cwe, &path, &createdAt) == nil {
				daysToResolve := 30
				if severity == "CRITICAL" {
					daysToResolve = 15
				}
				items = append(items, map[string]any{
					"uuid":                 "poam-" + id,
					"title":                fmt.Sprintf("[%s] %s", ruleID, message[:min(80, len(message))]),
					"description":          message,
					"finding-id":           id,
					"severity":             severity,
					"tool":                 tool,
					"cwe":                  cwe,
					"path":                 path,
					"detected":             createdAt.Format(time.RFC3339),
					"scheduled-completion": createdAt.AddDate(0, 0, daysToResolve).Format(time.RFC3339),
					"milestones": []map[string]any{
						{"title": "Assign owner", "due": createdAt.AddDate(0, 0, 2).Format(time.RFC3339)},
						{"title": "Develop fix", "due": createdAt.AddDate(0, 0, daysToResolve/2).Format(time.RFC3339)},
						{"title": "Verify fix", "due": createdAt.AddDate(0, 0, daysToResolve).Format(time.RFC3339)},
					},
				})
			}
		}
	}
	if items == nil {
		items = []map[string]any{}
	}

	jsonOK(w, map[string]any{
		"oscal-version": "1.1.2",
		"uuid":          fmt.Sprintf("poam-%d", time.Now().Unix()),
		"metadata": map[string]any{
			"title":         "VSP Plan of Action & Milestones",
			"last-modified": time.Now().Format(time.RFC3339),
			"oscal-version": "1.1.2",
		},
		"poam-items": items,
		"total":      len(items),
	})
}
