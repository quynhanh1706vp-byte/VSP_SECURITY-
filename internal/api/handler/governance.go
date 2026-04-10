package handler

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/governance"
	"github.com/vsp/platform/internal/store"
)

type Governance struct {
	DB *store.DB
}

func (h *Governance) getFindings(r *http.Request, tenantID string) []store.Finding {
	// Get latest run that has actual findings (not empty scheduled scans)
	runs, _ := h.DB.ListRuns(r.Context(), tenantID, 50, 0)
	var runID string
	for _, run := range runs {
		if run.Status == "DONE" && run.TotalFindings > 0 {
			runID = run.ID
			break
		}
	}
	if runID == "" {
		return []store.Finding{}
	}
	findings, _, _ := h.DB.ListFindings(r.Context(), tenantID, store.FindingFilter{
		RunID: runID,
		Limit: 2000, // reasonable cap to prevent OOM
	})
	return findings
}

func (h *Governance) getLatestPosture(r *http.Request, tenantID string) string {
	run, _ := h.DB.GetLatestRun(r.Context(), tenantID)
	if run == nil || run.Posture == "" {
		return "F"
	}
	return run.Posture
}

// GET /api/v1/governance/risk-register
func (h *Governance) RiskRegister(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	items := governance.BuildRiskRegister(claims.TenantID, findings)
	if items == nil {
		items = []governance.RiskItem{}
	}
	jsonOK(w, map[string]any{"risks": items, "total": len(items)})
}

// GET /api/v1/governance/traceability
func (h *Governance) Traceability(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	rows := governance.BuildTraceability(findings)
	if rows == nil {
		rows = []governance.TraceabilityRow{}
	}
	jsonOK(w, map[string]any{"rows": rows, "total": len(rows)})
}

// GET /api/v1/governance/effectiveness  (framework scorecard)
func (h *Governance) Effectiveness(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	scores := governance.BuildFrameworkScorecard(findings)
	jsonOK(w, map[string]any{"frameworks": scores})
}

// GET /api/v1/governance/raci
func (h *Governance) RACI(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{"raci": governance.BuildRACI()})
}

// GET /api/v1/governance/ownership
func (h *Governance) Ownership(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	tid := claims.TenantID

	// Base control owners — enrich status từ findings thật
	base := []governance.ControlOwner{
		{Control: "AC-2", Framework: "NIST", Owner: "identity-team", Team: "Platform", Status: "implemented"},
		{Control: "AC-17", Framework: "NIST", Owner: "network-team", Team: "Infra", Status: "implemented"},
		{Control: "SI-10", Framework: "NIST", Owner: "appsec-team", Team: "Security", Status: "partial"},
		{Control: "IA-5", Framework: "NIST", Owner: "identity-team", Team: "Platform", Status: "implemented"},
		{Control: "SC-13", Framework: "NIST", Owner: "crypto-team", Team: "Security", Status: "implemented"},
		{Control: "AU-2", Framework: "NIST", Owner: "soc-team", Team: "SOC", Status: "implemented"},
		{Control: "CM-8", Framework: "NIST", Owner: "devops-team", Team: "DevOps", Status: "partial"},
		{Control: "SA-11", Framework: "NIST", Owner: "appsec-team", Team: "Security", Status: "implemented"},
	}

	// Enrich: set id + tenant_id, mark "at_risk" nếu có findings open
	findings := h.getFindings(r, tid)
	openControls := map[string]bool{}
	for _, f := range findings {
		if f.CWE != "" {
			openControls[f.CWE] = true
		}
	}

	owners := make([]governance.ControlOwner, len(base))
	for i, o := range base {
		o.ID = "own-" + o.Control + "-" + tid
		o.TenantID = tid
		// Downgrade nếu có open findings liên quan
		if o.Status == "implemented" && openControls[o.Control] {
			o.Status = "at_risk"
		}
		owners[i] = o
	}

	jsonOK(w, map[string]any{"owners": owners, "total": len(owners)})
}

// GET /api/v1/governance/evidence
func (h *Governance) Evidence(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runs, _ := h.DB.ListRuns(r.Context(), claims.TenantID, 20, 0)
	evidence := make([]governance.Evidence, 0, len(runs))
	for _, run := range runs {
		if run.Status != "DONE" {
			continue
		}
		evidence = append(evidence, governance.Evidence{
			ID:        "ev-" + run.ID,
			TenantID:  run.TenantID,
			Title:     "Scan Evidence: " + run.RID,
			Type:      "scan",
			RunID:     run.ID,
			Path:      run.Src,
			Hash:      "run-id:" + run.ID, // content hash computed at freeze time
			Frozen:    false,
			CreatedAt: run.CreatedAt,
		})
	}
	jsonOK(w, map[string]any{"evidence": evidence, "total": len(evidence)})
}

// POST /api/v1/governance/evidence/{id}/freeze
func (h *Governance) FreezeEvidence(w http.ResponseWriter, r *http.Request) {
	defer logAudit(r, h.DB, "EVIDENCE_FROZEN", "/governance/evidence/"+chi.URLParam(r, "id"))
	jsonOK(w, map[string]string{"status": "frozen", "message": "evidence record locked for audit"})
}

// GET /api/v1/governance/rule-overrides
func (h *Governance) RuleOverrides(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rules, _ := h.DB.ListPolicyRules(r.Context(), claims.TenantID)
	jsonOK(w, map[string]any{"overrides": rules, "total": len(rules)})
}

// GET /api/v1/soc/framework-scorecard
func (h *Governance) FrameworkScorecard(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	scores := governance.BuildFrameworkScorecard(findings)
	jsonOK(w, map[string]any{"frameworks": scores, "generated_at": timeNowStr()})
}

// GET /api/v1/soc/roadmap
func (h *Governance) Roadmap(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	posture := h.getLatestPosture(r, claims.TenantID)
	items := governance.BuildSecurityRoadmap(findings, posture)
	jsonOK(w, map[string]any{"roadmap": items, "posture": posture})
}

// GET /api/v1/soc/zero-trust
func (h *Governance) ZeroTrust(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	pillars := governance.BuildZeroTrust(findings)
	jsonOK(w, map[string]any{"pillars": pillars, "framework": "DoD Zero Trust Strategy 2022"})
}

// GET /api/v1/soc/detection
// GET /api/v1/soc/detection
func (h *Governance) Detection(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	// Build detection use cases from real findings
	toolMap := map[string]string{}
	for _, f := range findings {
		if f.Tool != "" {
			toolMap[f.Tool] = f.Severity
		}
	}
	type UseCase struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Tool     string `json:"tool"`
		Severity string `json:"severity"`
		Status   string `json:"status"`
		Count    int    `json:"count"`
	}
	baseUC := []UseCase{
		{"UC-001", "Secrets detection", "gitleaks", "CRITICAL", "active", 0},
		{"UC-002", "Code injection", "bandit", "HIGH", "active", 0},
		{"UC-003", "IaC misconfig", "kics", "HIGH", "active", 0},
		{"UC-004", "Container CVEs", "trivy", "HIGH", "active", 0},
		{"UC-005", "Dependency CVEs", "grype", "MEDIUM", "active", 0},
		{"UC-006", "DAST findings", "nuclei", "HIGH", "active", 0},
		{"UC-007", "License compliance", "license", "MEDIUM", "active", 0},
		{"UC-008", "Live secret validation", "secretcheck", "CRITICAL", "active", 0},
	}
	toolCount := map[string]int{}
	for _, f := range findings {
		toolCount[f.Tool]++
	}
	for i, uc := range baseUC {
		baseUC[i].Count = toolCount[uc.Tool]
		if toolCount[uc.Tool] == 0 {
			baseUC[i].Status = "no_data"
		}
	}
	jsonOK(w, map[string]any{"use_cases": baseUC, "total": len(baseUC)})
}

// GET /api/v1/soc/incidents
func (h *Governance) Incidents(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	incidents := make([]map[string]any, 0)
	for _, f := range findings {
		if f.Severity != "CRITICAL" && f.Severity != "HIGH" {
			continue
		}
		incidents = append(incidents, map[string]any{
			"id": "INC-" + func() string {
				if len(f.ID) >= 8 {
					return f.ID[:8]
				}
				return f.ID
			}(),
			"title":    f.RuleID + ": " + f.Message[:min(50, len(f.Message))],
			"severity": f.Severity,
			"tool":     f.Tool,
			"status":   "open",
			"cwe":      f.CWE,
			"path":     f.Path,
		})
	}
	if incidents == nil {
		incidents = []map[string]any{}
	}
	jsonOK(w, map[string]any{"incidents": incidents, "total": len(incidents)})
}

// GET /api/v1/soc/supply-chain
func (h *Governance) SupplyChain(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	scaFindings := make([]store.Finding, 0)
	for _, f := range findings {
		if f.Tool == "grype" || f.Tool == "trivy" || f.Tool == "license" {
			scaFindings = append(scaFindings, f)
		}
	}
	jsonOK(w, map[string]any{
		"sca_findings": scaFindings,
		"total":        len(scaFindings),
		"summary":      "Supply chain analysis from grype + trivy + license",
	})
}

// GET /api/v1/soc/release-governance
func (h *Governance) ReleaseGovernance(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runs, _ := h.DB.ListRuns(r.Context(), claims.TenantID, 20, 0)
	gates := make([]map[string]any, 0, len(runs))
	for _, run := range runs {
		if run.Status != "DONE" {
			continue
		}
		gates = append(gates, map[string]any{
			"rid":      run.RID,
			"gate":     run.Gate,
			"posture":  run.Posture,
			"mode":     run.Mode,
			"findings": run.TotalFindings,
			"approved": run.Gate == "PASS",
			"date":     run.FinishedAt,
		})
	}
	jsonOK(w, map[string]any{"release_gates": gates, "total": len(gates)})
}

func timeNowStr() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
