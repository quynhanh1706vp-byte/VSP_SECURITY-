package handler

import (
	"net/http"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// FedRAMP control families mapped to VSP scan tools
var fedRAMPControls = []map[string]any{
	{"id":"AC-2",  "family":"Access Control",       "title":"Account Management",           "tool":"bandit,semgrep", "status":""},
	{"id":"AC-3",  "family":"Access Control",       "title":"Access Enforcement",           "tool":"bandit",         "status":""},
	{"id":"AC-17", "family":"Access Control",       "title":"Remote Access",                "tool":"semgrep,nikto",  "status":""},
	{"id":"AU-2",  "family":"Audit & Accountability","title":"Event Logging",               "tool":"bandit",         "status":""},
	{"id":"AU-9",  "family":"Audit & Accountability","title":"Protection of Audit Info",    "tool":"bandit,gitleaks","status":""},
	{"id":"CA-7",  "family":"Assessment",           "title":"Continuous Monitoring",        "tool":"all",            "status":""},
	{"id":"CM-2",  "family":"Config Management",    "title":"Baseline Configuration",       "tool":"kics,checkov",   "status":""},
	{"id":"CM-6",  "family":"Config Management",    "title":"Configuration Settings",       "tool":"kics,checkov",   "status":""},
	{"id":"CM-8",  "family":"Config Management",    "title":"System Component Inventory",   "tool":"grype,trivy",    "status":""},
	{"id":"IA-2",  "family":"Identification & Auth","title":"Multi-Factor Authentication",  "tool":"bandit,semgrep", "status":""},
	{"id":"IA-5",  "family":"Identification & Auth","title":"Authenticator Management",     "tool":"gitleaks",       "status":""},
	{"id":"RA-3",  "family":"Risk Assessment",      "title":"Risk Assessment",              "tool":"all",            "status":""},
	{"id":"RA-5",  "family":"Risk Assessment",      "title":"Vulnerability Monitoring",     "tool":"grype,trivy,nuclei","status":""},
	{"id":"SA-11", "family":"System & Services",    "title":"Developer Testing",            "tool":"bandit,semgrep,codeql","status":""},
	{"id":"SA-15", "family":"System & Services",    "title":"Development Process",          "tool":"semgrep,codeql","status":""},
	{"id":"SC-8",  "family":"System & Comms",       "title":"Transmission Confidentiality", "tool":"nikto,nuclei",   "status":""},
	{"id":"SC-28", "family":"System & Comms",       "title":"Protection at Rest",           "tool":"gitleaks",       "status":""},
	{"id":"SI-2",  "family":"System & Info Integrity","title":"Flaw Remediation",           "tool":"grype,trivy",    "status":""},
	{"id":"SI-3",  "family":"System & Info Integrity","title":"Malicious Code Protection",  "tool":"bandit,semgrep,codeql","status":""},
	{"id":"SI-10", "family":"System & Info Integrity","title":"Input Validation",           "tool":"bandit,semgrep", "status":""},
}

// CMMC Level 2 practices mapped to VSP
var cmmcPractices = []map[string]any{
	{"id":"AC.L2-3.1.1",  "domain":"Access Control",       "practice":"Limit system access to authorized users",       "tool":"bandit,semgrep","nist":"AC-2"},
	{"id":"AC.L2-3.1.2",  "domain":"Access Control",       "practice":"Limit system access to authorized transactions","tool":"bandit",        "nist":"AC-3"},
	{"id":"AU.L2-3.3.1",  "domain":"Audit & Accountability","practice":"Create and retain system audit logs",          "tool":"bandit",        "nist":"AU-2"},
	{"id":"CM.L2-3.4.1",  "domain":"Config Management",    "practice":"Establish baseline configs",                    "tool":"kics,checkov",  "nist":"CM-2"},
	{"id":"CM.L2-3.4.2",  "domain":"Config Management",    "practice":"Establish config change control",               "tool":"kics,checkov",  "nist":"CM-3"},
	{"id":"IA.L2-3.5.3",  "domain":"Identification & Auth","practice":"Multi-factor authentication",                   "tool":"bandit,semgrep","nist":"IA-2"},
	{"id":"IA.L2-3.5.10", "domain":"Identification & Auth","practice":"Employ cryptographically-protected passwords",  "tool":"gitleaks",      "nist":"IA-5"},
	{"id":"RA.L2-3.11.1", "domain":"Risk Assessment",      "practice":"Periodically assess risk",                      "tool":"all",           "nist":"RA-3"},
	{"id":"RA.L2-3.11.2", "domain":"Risk Assessment",      "practice":"Scan for vulnerabilities periodically",         "tool":"grype,trivy",   "nist":"RA-5"},
	{"id":"SA.L2-3.12.1", "domain":"Security Assessment",  "practice":"Periodically assess security controls",         "tool":"all",           "nist":"CA-7"},
	{"id":"SI.L2-3.14.1", "domain":"System & Info Integrity","practice":"Identify and manage flaws",                   "tool":"grype,trivy",   "nist":"SI-2"},
	{"id":"SI.L2-3.14.4", "domain":"System & Info Integrity","practice":"Update malicious code protection",            "tool":"bandit,semgrep","nist":"SI-3"},
	{"id":"SI.L2-3.14.6", "domain":"System & Info Integrity","practice":"Monitor for attacks and indicators",          "tool":"nuclei,nikto",  "nist":"SI-4"},
}

type Compliance struct{ DB *store.DB }

// GET /api/v1/compliance/fedramp
func (h *Compliance) FedRAMP(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	
	// Get latest run findings to determine control status
	runs, _ := h.DB.ListRuns(r.Context(), claims.TenantID, 5, 0)
	toolsUsed := map[string]bool{}
	for _, run := range runs {
		if run.Status == "DONE" {
			toolsUsed[run.Mode] = true
		}
	}

	// Score controls based on tools run
	controls := make([]map[string]any, len(fedRAMPControls))
	for i, c := range fedRAMPControls {
		ctrl := map[string]any{}
		for k, v := range c { ctrl[k] = v }
		ctrl["status"] = "not_assessed"
		if c["tool"] == "all" || len(toolsUsed) > 0 {
			ctrl["status"] = "assessed"
		}
		controls[i] = ctrl
	}

	assessed := 0
	for _, c := range controls {
		if c["status"] == "assessed" { assessed++ }
	}

	jsonOK(w, map[string]any{
		"framework":      "FedRAMP Moderate",
		"total_controls": len(controls),
		"assessed":       assessed,
		"coverage_pct":   int(float64(assessed)/float64(len(controls))*100),
		"controls":       controls,
	})
}

// GET /api/v1/compliance/cmmc
func (h *Compliance) CMMC(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runs, _ := h.DB.ListRuns(r.Context(), claims.TenantID, 5, 0)
	hasRuns := len(runs) > 0

	practices := make([]map[string]any, len(cmmcPractices))
	for i, p := range cmmcPractices {
		pr := map[string]any{}
		for k, v := range p { pr[k] = v }
		pr["status"] = "not_assessed"
		if hasRuns { pr["status"] = "assessed" }
		practices[i] = pr
	}

	assessed := 0
	for _, p := range practices {
		if p["status"] == "assessed" { assessed++ }
	}

	jsonOK(w, map[string]any{
		"framework":       "CMMC Level 2",
		"total_practices": len(practices),
		"assessed":        assessed,
		"coverage_pct":    int(float64(assessed)/float64(len(practices))*100),
		"practices":       practices,
	})
}

// GET /api/v1/compliance/oscal/ar
func (h *Compliance) OSCALAR(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runs, _ := h.DB.ListRuns(r.Context(), claims.TenantID, 1, 0)
	rid := ""
	if len(runs) > 0 { rid = runs[0].RID }
	jsonOK(w, map[string]any{
		"oscal-version": "1.1.2",
		"type": "assessment-results",
		"metadata": map[string]any{
			"title": "VSP Security Assessment Results",
			"last-modified": "2026-03-27",
		},
		"results": []map[string]any{{
			"title": "Automated Security Scan",
			"start": "2026-03-27",
			"reviewed-controls": map[string]any{"control-selections": fedRAMPControls},
			"rid": rid,
		}},
	})
}

// GET /api/v1/compliance/oscal/poam
func (h *Compliance) OSCALPOAM(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"oscal-version": "1.1.2",
		"type":          "plan-of-action-and-milestones",
		"metadata":      map[string]any{"title": "VSP POA&M"},
		"poam-items":    []map[string]any{},
	})
}
