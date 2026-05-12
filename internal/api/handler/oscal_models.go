package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// OSCALModels — handlers for AP / AR / POAM (real data from DB)
type OSCALModels struct {
	DB *store.DB
}

// ─── helper: tenant resolver ─────────────────────────────────────────────
func (h *OSCALModels) tenantUUID(r *http.Request) string {
	if claims, ok := auth.FromContext(r.Context()); ok && claims.TenantID != "" {
		return claims.TenantID
	}
	return "1bdf7f20-dbb3-4116-815f-26b4dc747e76" // default tenant fallback
}

// ─── GET /api/p4/oscal/ap (Assessment Plan) ──────────────────────────────
func (h *OSCALModels) AssessmentPlan(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantUUID(r)
	docUUID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	// Get distinct tools used in scans
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT tool, COUNT(*) AS cnt FROM findings WHERE tenant_id = $1
		 GROUP BY tool ORDER BY cnt DESC LIMIT 20`, tenant)
	if err != nil {
		jsonInternalError(w, r, "query findings", err)
		return
	}
	defer rows.Close()

	type tool struct {
		Name  string
		Count int
	}
	var tools []tool
	for rows.Next() {
		var t tool
		if err := rows.Scan(&t.Name, &t.Count); err == nil {
			tools = append(tools, t)
		}
	}

	// Get total runs
	var totalRuns int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM runs WHERE tenant_id=$1`, tenant).Scan(&totalRuns)

	// Build OSCAL Assessment Plan 1.1.2
	tasks := []map[string]interface{}{}
	toolDescriptions := map[string]string{
		"kics":       "Infrastructure as Code (IaC) static analysis — Terraform, CloudFormation, Kubernetes manifests",
		"gosec":      "Go source code security scanner",
		"bandit":     "Python source code security scanner",
		"syft":       "Software Bill of Materials (SBOM) generation",
		"semgrep":    "Multi-language static analysis with custom rules",
		"checkov":    "IaC and policy-as-code static analysis",
		"nmap":       "Network port and service discovery",
		"codeql":     "Semantic code analysis (GitHub Advanced Security)",
		"grype":      "Container image and OS vulnerability scanner",
		"hadolint":   "Dockerfile linter and best-practice checker",
		"trivy":      "Container vulnerability and misconfiguration scanner",
		"trufflehog": "Secrets detection in git history",
	}
	for _, t := range tools {
		desc := toolDescriptions[t.Name]
		if desc == "" {
			desc = "Security scanning tool: " + t.Name
		}
		tasks = append(tasks, map[string]interface{}{
			"uuid":        uuid.New().String(),
			"type":        "action",
			"title":       "Run " + t.Name,
			"description": desc,
			"props": []map[string]string{
				{"name": "tool-name", "value": t.Name},
				{"name": "findings-historical", "value": oscal2Int(t.Count)},
			},
		})
	}

	doc := map[string]interface{}{
		"assessment-plan": map[string]interface{}{
			"uuid": docUUID,
			"metadata": map[string]interface{}{
				"title":         "VSP Security Assessment Plan",
				"published":     now,
				"last-modified": now,
				"version":       "1.0",
				"oscal-version": "1.1.2",
				"parties": []map[string]interface{}{
					{
						"uuid": uuid.New().String(),
						"type": "organization",
						"name": "VSP Security Platform",
					},
				},
			},
			"import-ssp": map[string]string{
				"href": "#vsp-ssp",
			},
			"reviewed-controls": map[string]interface{}{
				"control-selections": []map[string]interface{}{
					{
						"description": "FedRAMP Moderate Baseline",
						"include-all": map[string]interface{}{},
					},
				},
			},
			"assessment-subjects": []map[string]interface{}{
				{
					"type":        "component",
					"description": "All components within VSP scope including source code, dependencies, container images, IaC manifests, and network services.",
					"include-all": map[string]interface{}{},
				},
			},
			"tasks": tasks,
			"terms-and-conditions": map[string]interface{}{
				"parts": []map[string]interface{}{
					{
						"name":  "method",
						"prose": "Methodology follows NIST SP 800-115 Technical Guide to Information Security Testing and Assessment. " + oscal2Int(totalRuns) + " historical scan runs analyzed.",
					},
				},
			},
		},
	}
	oscal2SaveCache(h.DB, r.Context(), tenant, "assessment-plan", docUUID, "VSP Security Assessment Plan", doc)
	jsonOK(w, doc)
}

// ─── GET /api/p4/oscal/ar (Assessment Results) ───────────────────────────
func (h *OSCALModels) AssessmentResults(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantUUID(r)
	docUUID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	// Severity counts
	type sevCount struct {
		Severity string
		Count    int
	}
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT severity, COUNT(*) FROM findings WHERE tenant_id=$1
		 GROUP BY severity ORDER BY 2 DESC`, tenant)
	if err != nil {
		jsonInternalError(w, r, "severity query", err)
		return
	}
	defer rows.Close()
	var sevs []sevCount
	for rows.Next() {
		var s sevCount
		if err := rows.Scan(&s.Severity, &s.Count); err == nil {
			sevs = append(sevs, s)
		}
	}

	// Top findings (highest CVSS, capped at 100 for performance)
	topRows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id, tool, severity, COALESCE(rule_id,'') AS rule_id,
		        COALESCE(message,'') AS message, COALESCE(path,'') AS path,
		        COALESCE(cwe,'') AS cwe, COALESCE(cvss,0) AS cvss
		 FROM findings WHERE tenant_id=$1
		 ORDER BY cvss DESC NULLS LAST, severity DESC
		 LIMIT 100`, tenant)
	if err != nil {
		jsonInternalError(w, r, "top findings query", err)
		return
	}
	defer topRows.Close()

	findings := []map[string]interface{}{}
	for topRows.Next() {
		var id, tool, sev, ruleID, msg, path, cwe string
		var cvss float64
		if err := topRows.Scan(&id, &tool, &sev, &ruleID, &msg, &path, &cwe, &cvss); err != nil {
			continue
		}
		findings = append(findings, map[string]interface{}{
			"uuid":        id,
			"title":       oscal2FirstNonEmpty(msg, ruleID, "Finding "+id[:8]),
			"description": oscal2FindingDesc(tool, cwe, path),
			"props": []map[string]string{
				{"name": "tool", "value": tool},
				{"name": "severity", "value": sev},
				{"name": "cvss", "value": oscal2Float(cvss)},
				{"name": "rule-id", "value": ruleID},
				{"name": "cwe", "value": cwe},
			},
			"target": map[string]interface{}{
				"type":      "component",
				"target-id": "vsp-platform",
				"status": map[string]string{
					"state": oscal2SevToState(sev),
				},
			},
		})
	}

	// Build risk summary
	riskSummary := map[string]int{}
	for _, s := range sevs {
		riskSummary[s.Severity] = s.Count
	}
	totalFindings := 0
	for _, n := range riskSummary {
		totalFindings += n
	}

	doc := map[string]interface{}{
		"assessment-results": map[string]interface{}{
			"uuid": docUUID,
			"metadata": map[string]interface{}{
				"title":         "VSP Security Assessment Results",
				"published":     now,
				"last-modified": now,
				"version":       "1.0",
				"oscal-version": "1.1.2",
			},
			"import-ap": map[string]string{
				"href": "#vsp-ap",
			},
			"results": []map[string]interface{}{
				{
					"uuid":        uuid.New().String(),
					"title":       "Continuous monitoring assessment results",
					"description": "Aggregated results from " + oscal2Int(totalFindings) + " findings across all configured scanning tools.",
					"start":       now,
					"end":         now,
					"reviewed-controls": map[string]interface{}{
						"control-selections": []map[string]interface{}{
							{"include-all": map[string]interface{}{}},
						},
					},
					"findings":        oscal2TruncateFindings(findings, 50),
					"finding-summary": riskSummary,
					"local-definitions": map[string]interface{}{
						"components": []map[string]interface{}{
							{
								"uuid":        "vsp-platform",
								"type":        "service",
								"title":       "VSP Security Platform",
								"description": "Vulnerability scanning and security platform under continuous assessment",
								"status":      map[string]string{"state": "operational"},
							},
						},
					},
				},
			},
		},
	}
	oscal2SaveCache(h.DB, r.Context(), tenant, "assessment-results", docUUID, "VSP Security Assessment Results", doc)
	jsonOK(w, doc)
}

// ─── GET /api/p4/oscal/poam (POA&M) ──────────────────────────────────────
func (h *OSCALModels) POAM(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantUUID(r)
	docUUID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	// p4_poam_items uses TEXT tenant_id, not UUID — query both
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id, COALESCE(weakness_name,'') AS wn, COALESCE(control_id,'') AS cid,
		        COALESCE(severity,'') AS sev, COALESCE(status,'open') AS st,
		        COALESCE(mitigation_plan,'') AS mp, COALESCE(finding_id,'') AS fid,
		        scheduled_completion, created_at
		 FROM p4_poam_items
		 WHERE tenant_id = $1 OR tenant_id = 'default' OR tenant_id IS NULL
		 ORDER BY created_at DESC LIMIT 200`, tenant)
	if err != nil {
		jsonInternalError(w, r, "poam query", err)
		return
	}
	defer rows.Close()

	poamItems := []map[string]interface{}{}
	statusCounts := map[string]int{}
	severityCounts := map[string]int{}
	for rows.Next() {
		var id, wn, cid, sev, st, mp, fid string
		var sched, created interface{}
		if err := rows.Scan(&id, &wn, &cid, &sev, &st, &mp, &fid, &sched, &created); err != nil {
			continue
		}
		statusCounts[st]++
		severityCounts[sev]++
		item := map[string]interface{}{
			"uuid":        uuid.New().String(),
			"title":       wn,
			"description": oscal2Truncate(mp, 800),
			"props": []map[string]string{
				{"name": "poam-id", "value": id},
				{"name": "control-id", "value": cid},
				{"name": "severity", "value": sev},
				{"name": "status", "value": st},
			},
		}
		if fid != "" {
			item["related-findings"] = []map[string]string{{"finding-uuid": fid}}
		}
		if sched != nil {
			if t, ok := sched.(time.Time); ok && !t.IsZero() {
				item["milestones"] = []map[string]interface{}{
					{
						"uuid":        uuid.New().String(),
						"title":       "Scheduled completion",
						"description": "Planned mitigation date per SLA",
						"end":         t.UTC().Format(time.RFC3339),
					},
				}
			}
		}
		poamItems = append(poamItems, item)
	}

	doc := map[string]interface{}{
		"plan-of-action-and-milestones": map[string]interface{}{
			"uuid": docUUID,
			"metadata": map[string]interface{}{
				"title":         "VSP Plan of Action and Milestones",
				"published":     now,
				"last-modified": now,
				"version":       "1.0",
				"oscal-version": "1.1.2",
			},
			"import-ssp": map[string]string{
				"href": "#vsp-ssp",
			},
			"system-id": map[string]string{
				"identifier-type": "https://fedramp.gov",
				"id":              "VSP-DOD-2025-001",
			},
			"poam-items":       poamItems,
			"status-summary":   statusCounts,
			"severity-summary": severityCounts,
		},
	}
	oscal2SaveCache(h.DB, r.Context(), tenant, "poam", docUUID, "VSP Plan of Action and Milestones", doc)
	jsonOK(w, doc)
}

// ─── helpers ──────────────────────────────────────────────────────────────
func oscal2Int(n int) string {
	return oscal2FormatInt(n)
}

func oscal2Float(f float64) string {
	return oscal2FormatFloat(f)
}

func oscal2FormatInt(n int) string {
	if n == 0 {
		return "0"
	}
	return oscal2Number(float64(n))
}

func oscal2FormatFloat(f float64) string {
	return oscal2Number(f)
}

func oscal2Number(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func oscal2FirstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func oscal2Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func oscal2TruncateFindings(f []map[string]interface{}, n int) []map[string]interface{} {
	if len(f) <= n {
		return f
	}
	return f[:n]
}

func oscal2SevToState(sev string) string {
	switch sev {
	case "critical", "CRITICAL":
		return "implemented-but-with-deviations"
	case "high", "HIGH":
		return "implemented-but-with-deviations"
	case "medium", "MEDIUM":
		return "implemented"
	case "low", "LOW", "info", "INFO":
		return "implemented"
	}
	return "implemented"
}

func oscal2FindingDesc(tool, cwe, path string) string {
	desc := "Detected by " + tool
	if cwe != "" && cwe != "—" {
		desc += " (" + cwe + ")"
	}
	desc += ". Path: " + oscal2Truncate(path, 200)
	return desc
}

// Save generated doc to oscal_documents table (best-effort cache)
func oscal2SaveCache(db *store.DB, ctx context.Context, tenant string, modelType string, docUUID string, title string, doc map[string]interface{}) {
	docJSON, _ := json.Marshal(doc)
	_, _ = db.Pool().Exec(ctx,
		`INSERT INTO oscal_documents (tenant_id, model_type, document_uuid, title, version, oscal_version, document_json, generated_at)
		 VALUES ($1::uuid, $2, $3, $4, '1.0', '1.1.2', $5::jsonb, NOW())
		 ON CONFLICT (document_uuid) DO UPDATE SET document_json=EXCLUDED.document_json, generated_at=NOW()`,
		tenant, modelType, docUUID, title, string(docJSON))
}
