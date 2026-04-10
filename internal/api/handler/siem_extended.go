package handler

import (
	"context"
	"fmt"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/viper"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/siem"
	"strings"

	"github.com/vsp/platform/internal/store"
	aiPkg "github.com/vsp/platform/internal/ai"
	licenseScanner "github.com/vsp/platform/internal/scanner/license"
	"github.com/vsp/platform/internal/scanner/secretcheck"
	"github.com/vsp/platform/internal/threatintel"
	"github.com/rs/zerolog/log"
)

// ── Correlation ───────────────────────────────────────────────

type Correlation struct{ DB *store.DB }

func (h *Correlation) ListRules(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rules, err := h.DB.ListCorrelationRules(r.Context(), claims.TenantID)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }
	if rules == nil { rules = []store.CorrelationRule{} }
	jsonOK(w, map[string]any{"rules": rules, "total": len(rules)})
}

func (h *Correlation) CreateRule(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req struct {
		Name      string   `json:"name"`
		Sources   []string `json:"sources"`
		WindowMin int      `json:"window_min"`
		Severity  string   `json:"severity"`
		Condition string   `json:"condition"`
		Enabled   bool     `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest); return
	}
	if req.Name == "" { jsonError(w, "name required", http.StatusBadRequest); return }
	if len(req.Name) > 200 { req.Name = req.Name[:200] }
	if req.WindowMin <= 0 { req.WindowMin = 5 }
	if req.WindowMin > 1440 { req.WindowMin = 1440 } // max 24h
	validSevs := map[string]bool{"CRITICAL":true,"HIGH":true,"MEDIUM":true,"LOW":true}
	if !validSevs[req.Severity] { req.Severity = "HIGH" }
	if req.Sources == nil  { req.Sources = []string{"scan"} }

	id, err := h.DB.CreateCorrelationRule(r.Context(), store.CorrelationRule{
		TenantID:  claims.TenantID,
		Name:      req.Name,
		Sources:   req.Sources,
		WindowMin: req.WindowMin,
		Severity:  req.Severity,
		Condition: req.Condition,
		Enabled:   req.Enabled,
	})
	if err != nil { jsonError(w, "internal server error", http.StatusInternalServerError); return }
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": id, "name": req.Name, "status": "created"})
}

func (h *Correlation) ToggleRule(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	enabled, err := h.DB.ToggleCorrelationRule(r.Context(), claims.TenantID, id)
	if err != nil { jsonError(w, "not found", http.StatusNotFound); return }
	jsonOK(w, map[string]any{"id": id, "enabled": enabled})
}

func (h *Correlation) DeleteRule(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	h.DB.DeleteCorrelationRule(r.Context(), claims.TenantID, chi.URLParam(r, "id")) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

func (h *Correlation) ListIncidents(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit := 50
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 { if l > 500 { l = 500 }; limit = l }
	incidents, err := h.DB.ListIncidents(r.Context(), claims.TenantID,
		r.URL.Query().Get("status"), r.URL.Query().Get("severity"), limit)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }
	if incidents == nil { incidents = []store.Incident{} }
	jsonOK(w, map[string]any{"incidents": incidents, "total": len(incidents)})
}

func (h *Correlation) CreateIncident(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req struct {
		Title      string          `json:"title"`
		Severity   string          `json:"severity"`
		RuleID     string          `json:"rule_id"`
		SourceRefs json.RawMessage `json:"source_refs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest); return
	}
	if req.Title == "" { jsonError(w, "title required", http.StatusBadRequest); return }
	if req.Severity == "" { req.Severity = "HIGH" }
	if req.SourceRefs == nil { req.SourceRefs = json.RawMessage("{}") }
	var ruleID *string
	if req.RuleID != "" { ruleID = &req.RuleID }
	id, err := h.DB.CreateIncident(r.Context(), store.Incident{
		TenantID:   claims.TenantID,
		Title:      req.Title,
		Severity:   req.Severity,
		RuleID:     ruleID,
		SourceRefs: req.SourceRefs,
	})
	if err != nil { jsonError(w, "internal server error", http.StatusInternalServerError); return }
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": id, "status": "created"})
}


func (h *Correlation) ResolveIncident(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	var req struct { Status string `json:"status"` }
	json.NewDecoder(r.Body).Decode(&req)
	if req.Status == "" { req.Status = "resolved" }
	if req.Status != "resolved" && req.Status != "open" && req.Status != "investigating" && req.Status != "archived" {
		jsonError(w, "invalid status", http.StatusBadRequest); return
	}
	if err := h.DB.UpdateIncidentStatus(r.Context(), claims.TenantID, id, req.Status); err != nil {
		jsonError(w, "not found", http.StatusNotFound); return
	}
	jsonOK(w, map[string]any{"id": id, "status": req.Status})
}

func (h *Correlation) GetIncident(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	inc, err := h.DB.GetIncident(r.Context(), claims.TenantID, id)
	if err != nil { jsonError(w, "not found", http.StatusNotFound); return }
	jsonOK(w, inc)
}

// ── SOAR ──────────────────────────────────────────────────────

type SOAR struct{ DB *store.DB }

func (h *SOAR) ListPlaybooks(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	pbs, err := h.DB.ListPlaybooks(r.Context(), claims.TenantID)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }
	if pbs == nil { pbs = []store.Playbook{} }
	jsonOK(w, map[string]any{"playbooks": pbs, "total": len(pbs)})
}

func (h *SOAR) CreatePlaybook(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Trigger     string          `json:"trigger"`
		SevFilter   string          `json:"sev_filter"`
		Steps       json.RawMessage `json:"steps"`
		Enabled     bool            `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest); return
	}
	if req.Name == "" { jsonError(w, "name required", http.StatusBadRequest); return }
	if req.SevFilter == "" { req.SevFilter = "any" }
	if req.Steps == nil    { req.Steps = json.RawMessage("[]") }
	id, err := h.DB.CreatePlaybook(r.Context(), store.Playbook{
		TenantID:    claims.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Trigger:     req.Trigger,
		SevFilter:   req.SevFilter,
		Steps:       req.Steps,
		Enabled:     req.Enabled,
	})
	if err != nil { jsonError(w, "internal server error", http.StatusInternalServerError); return }
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": id, "name": req.Name, "status": "created"})
}

func (h *SOAR) TogglePlaybook(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	enabled, err := h.DB.TogglePlaybook(r.Context(), claims.TenantID, id)
	if err != nil { jsonError(w, "not found", http.StatusNotFound); return }
	jsonOK(w, map[string]any{"id": id, "enabled": enabled})
}

func (h *SOAR) RunPlaybook(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")

	// Load playbook steps
	var name string
	var stepsRaw []byte
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT name, steps FROM playbooks WHERE id=$1 AND tenant_id=$2`,
		id, claims.TenantID).Scan(&name, &stepsRaw)
	if err != nil { jsonError(w, "playbook not found", http.StatusNotFound); return }

	var ctxRaw json.RawMessage
	json.NewDecoder(r.Body).Decode(&ctxRaw) //nolint:errcheck
	if ctxRaw == nil { ctxRaw = json.RawMessage(`{"trigger":"manual"}`) }

	runID, err := h.DB.CreatePlaybookRun(r.Context(), id, claims.TenantID, "manual", ctxRaw)
	if err != nil { jsonError(w, "internal server error", http.StatusInternalServerError); return }

	// Parse run context
	var runCtxMap map[string]string
	if err := json.Unmarshal(ctxRaw, &runCtxMap); err != nil { log.Warn().Err(err).Caller().Msg("ignored error") }
	if runCtxMap == nil { runCtxMap = map[string]string{} }

	// Parse + validate steps
	var rawSteps []map[string]string
	if err := json.Unmarshal(stepsRaw, &rawSteps); err != nil { log.Warn().Err(err).Caller().Msg("ignored error") }
	// Validate step types — prevent injection of unknown step types
	validStepTypes := map[string]bool{
		"condition":true,"notify":true,"ticket":true,"block":true,
		"webhook":true,"enrich":true,"remediate":true,"wait":true,
	}
	for _, step := range rawSteps {
		if t := step["Type"]; t != "" && !validStepTypes[t] {
			jsonError(w, "invalid step type: "+t, http.StatusBadRequest)
			return
		}
	}
	// Load executor config từ env/config
	rc := siem.RunCtx{
		TenantID:        claims.TenantID,
		RunID:           runID,
		Trigger:         runCtxMap["trigger"],
		Severity:        runCtxMap["severity"],
		FindingID:       runCtxMap["finding_id"],
		Gate:            runCtxMap["gate"],
		SlackWebhookURL: viper.GetString("integrations.slack_webhook"),
		JiraURL:         viper.GetString("integrations.jira_url"),
		JiraToken:       viper.GetString("integrations.jira_token"),
		JiraProject:     viper.GetString("integrations.jira_project"),
		GitHubToken:     viper.GetString("integrations.github_token"),
		GitHubRepo:      viper.GetString("integrations.github_repo"),
		PagerDutyKey:    viper.GetString("integrations.pagerduty_key"),
	}
	if rc.Gate == "" { rc.Gate = "FAIL" }
	if rc.Severity == "" { rc.Severity = "HIGH" }

	// Execute async
	go siem.ExecutePlaybook(context.Background(), h.DB, runID, rawSteps, rc) //nolint:gosec // G118: playbook runs async beyond request lifetime

	jsonOK(w, map[string]any{"run_id": runID, "playbook": name, "status": "running"})
}

func (h *SOAR) Trigger(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req struct {
		Trigger  string `json:"trigger"`
		Severity string `json:"severity"`
		RunID    string `json:"run_id"`
		Findings int    `json:"findings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest); return
	}
	if req.Severity == "" { req.Severity = "any" }
	pbs, err := h.DB.FindEnabledPlaybooks(r.Context(), claims.TenantID, req.Trigger, req.Severity)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }
	ctx := json.RawMessage(`{"trigger":"` + req.Trigger + `","run_id":"` + req.RunID + `"}`)
	for _, pb := range pbs {
		pbID := pb.ID
		h.DB.CreatePlaybookRun(r.Context(), pbID, claims.TenantID, req.Trigger, ctx) //nolint:errcheck
	}
	jsonOK(w, map[string]any{"triggered": len(pbs), "trigger": req.Trigger})
}

func (h *SOAR) ListRuns(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 { if l > 500 { l = 500 }; limit = l }
	runs, err := h.DB.ListPlaybookRuns(r.Context(), claims.TenantID, limit)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }
	if runs == nil { runs = []store.PlaybookRun{} }
	jsonOK(w, map[string]any{"runs": runs, "total": len(runs)})
}

// ── Log sources ───────────────────────────────────────────────

type LogSources struct{ DB *store.DB }

func (h *LogSources) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	sources, err := h.DB.ListLogSources(r.Context(), claims.TenantID)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }
	if sources == nil { sources = []store.LogSource{} }
	jsonOK(w, map[string]any{"sources": sources, "total": len(sources)})
}

func (h *LogSources) Create(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req store.LogSource
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest); return
	}
	if req.Name == "" { jsonError(w, "name required", http.StatusBadRequest); return }
	if req.Protocol == "" { req.Protocol = "syslog-udp" }
	if req.Format == ""   { req.Format = "syslog-rfc3164" }
	if req.Port == 0      { req.Port = 514 }
	req.TenantID = claims.TenantID
	id, err := h.DB.CreateLogSource(r.Context(), req)
	if err != nil { jsonError(w, "internal server error", http.StatusInternalServerError); return }
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": id, "name": req.Name, "status": "created"})
}

func (h *LogSources) Delete(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	h.DB.DeleteLogSource(r.Context(), claims.TenantID, chi.URLParam(r, "id")) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

func (h *LogSources) Test(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	if err := h.DB.TestLogSource(r.Context(), claims.TenantID, chi.URLParam(r, "id")); err != nil {
		jsonError(w, "not found", http.StatusNotFound); return
	}
	jsonOK(w, map[string]any{"status": "ok", "tested_at": time.Now()})
}

func (h *LogSources) Stats(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	total, online, errCount, eps := h.DB.LogSourceStats(r.Context(), claims.TenantID)
	// Count today events from log_events
	var totalToday int64
	h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM log_events WHERE tenant_id=$1 AND ts >= CURRENT_DATE`,
		claims.TenantID).Scan(&totalToday) //nolint:errcheck
	// Count queue (events in last 5s not yet processed)
	var queue int
	h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM log_events WHERE tenant_id=$1 AND created_at >= NOW()-interval'5 seconds'`,
		claims.TenantID).Scan(&queue) //nolint:errcheck
	jsonOK(w, map[string]any{
		"total": total, "online": online, "errors": errCount,
		"eps": eps, "queue": queue, "total_today": totalToday,
	})
}

// ── Threat intel ──────────────────────────────────────────────

type ThreatIntel struct{ DB *store.DB }

func (h *ThreatIntel) ListIOCs(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 { if l > 500 { l = 500 }; limit = l }
	iocs, err := h.DB.ListIOCs(r.Context(), r.URL.Query().Get("type"), limit)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }
	if iocs == nil { iocs = []store.IOC{} }
	jsonOK(w, map[string]any{"iocs": iocs, "total": len(iocs)})
}

func (h *ThreatIntel) ListFeeds(w http.ResponseWriter, r *http.Request) {
	type Feed struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		IOCs   int    `json:"iocs"`
		Last   string `json:"last"`
	}
	names := []string{"NVD / NIST","OSV database","MISP community","AlienVault OTX","AbuseIPDB","STIX / TAXII"}
	feeds := make([]Feed, len(names))
	for i, name := range names {
		cnt := h.DB.IOCFeedCounts(r.Context(), name)
		status := "ok"
		if cnt == 0 && i >= 4 { status = map[int]string{4:"warn",5:"err"}[i] }
		feeds[i] = Feed{Name: name, Status: status, IOCs: cnt, Last: "5m"}
	}
	jsonOK(w, map[string]any{"feeds": feeds, "total": len(feeds)})
}

func (h *ThreatIntel) Matches(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l, _ := strconv.Atoi(r.URL.Query().Get("limit")); l > 0 { limit = l }
	iocs, err := h.DB.ListIOCs(r.Context(), "", limit)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }
	matched := make([]store.IOC, 0)
	for _, ioc := range iocs {
		if ioc.Matched { matched = append(matched, ioc) }
	}
	jsonOK(w, map[string]any{"matches": matched, "total": len(matched)})
}

func (h *ThreatIntel) MITRE(w http.ResponseWriter, r *http.Request) {
	type Tactic struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	cweMap := map[string]string{
		"CWE-78":"TA0002","CWE-79":"TA0001","CWE-89":"TA0001",
		"CWE-798":"TA0006","CWE-200":"TA0009","CWE-22":"TA0007",
		"CWE-287":"TA0001","CWE-502":"TA0002",
	}
	counts := map[string]int{}
	for cwe, tactic := range cweMap {
		counts[tactic] += h.DB.FindingCWECount(r.Context(), cwe)
	}
	tactics := []Tactic{
		{"TA0001","Initial access",counts["TA0001"]},
		{"TA0002","Execution",counts["TA0002"]},
		{"TA0003","Persistence",0},
		{"TA0004","Priv esc",0},
		{"TA0005","Def evasion",0},
		{"TA0006","Cred access",counts["TA0006"]},
		{"TA0007","Discovery",counts["TA0007"]},
		{"TA0008","Lateral mov",0},
		{"TA0009","Collection",counts["TA0009"]},
		{"TA0010","Exfiltration",0},
	}
	jsonOK(w, map[string]any{"tactics": tactics})
}

func (h *ThreatIntel) SyncFeeds(w http.ResponseWriter, r *http.Request) {
	go h.DB.SeedIOCsFromFindings(r.Context())
	jsonOK(w, map[string]any{"status": "sync_started", "started_at": time.Now()})
}

// ── Threat Intel Enrichment (NVD + EPSS + KEV) ────────────────────────────

var _tiClient = threatintel.NewClient()

func init() {
	go func() {
		ctx := context.Background()
		_tiClient.LoadKEV(ctx) //nolint:errcheck
	}()
}

// GET /api/v1/ti/enrich?cve=CVE-2024-45337
func (h *ThreatIntel) Enrich(w http.ResponseWriter, r *http.Request) {
	cveID := strings.TrimSpace(r.URL.Query().Get("cve"))
	if cveID == "" {
		jsonError(w, "cve param required", http.StatusBadRequest)
		return
	}
	enr, err := _tiClient.EnrichCVE(r.Context(), cveID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	jsonOK(w, enr)
}

// POST /api/v1/ti/enrich/batch
func (h *ThreatIntel) EnrichBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CVEs []string `json:"cves"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if len(req.CVEs) == 0 {
		jsonError(w, "cves required", http.StatusBadRequest)
		return
	}
	if len(req.CVEs) > 50 {
		req.CVEs = req.CVEs[:50]
	}
	results := _tiClient.EnrichBatch(r.Context(), req.CVEs)
	jsonOK(w, map[string]any{"enrichments": results, "total": len(results)})
}

// GET /api/v1/vsp/findings/dedup — deduplicated findings với fingerprint
func (h *ThreatIntel) DedupFindings(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Load all findings for tenant
	findings, total, err := h.DB.ListFindings(r.Context(), claims.TenantID, store.FindingFilter{
		Limit: 5000,
	})
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	// Deduplicate
	deduped := threatintel.Deduplicate(findings)

	// Stats
	persistent := 0
	for _, d := range deduped {
		if d.IsPersistent { persistent++ }
	}

	jsonOK(w, map[string]any{
		"findings":        deduped,
		"total_raw":       total,
		"total_unique":    len(deduped),
		"persistent":      persistent,
		"dedup_ratio":     fmt.Sprintf("%.1f%%", float64(int64(len(deduped))-total)*-1/float64(total)*100),
	})
}

// GET /api/v1/vsp/findings/chains — detect attack chains
func (h *ThreatIntel) ExploitChains(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	findings, _, err := h.DB.ListFindings(r.Context(), claims.TenantID, store.FindingFilter{Limit: 5000})
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	chains := threatintel.DetectChains(findings)
	if chains == nil {
		chains = []threatintel.ExploitChain{}
	}
	jsonOK(w, map[string]any{
		"chains": chains,
		"total":  len(chains),
	})
}

// POST /api/v1/ai/analyze/findings — semantic analysis với Claude
func (h *ThreatIntel) SemanticAnalyze(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		FindingIDs []string `json:"finding_ids"` // optional: specific findings
		MaxItems   int      `json:"max_items"`   // default 5
		Severity   string   `json:"severity"`    // filter: CRITICAL/HIGH/etc
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	if req.MaxItems == 0 { req.MaxItems = 5 }
	if req.MaxItems > 20 { req.MaxItems = 20 }

	filter := store.FindingFilter{Limit: 500}
	if req.Severity != "" { filter.Severity = req.Severity }

	findings, _, err := h.DB.ListFindings(r.Context(), claims.TenantID, filter)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	// Filter by specific IDs if provided
	if len(req.FindingIDs) > 0 {
		idSet := make(map[string]bool)
		for _, id := range req.FindingIDs { idSet[id] = true }
		filtered := findings[:0]
		for _, f := range findings {
			if idSet[f.ID] { filtered = append(filtered, f) }
		}
		findings = filtered
	}

	analyzer := aiPkg.NewSemanticAnalyzer()
	result, err := analyzer.AnalyzeBatch(r.Context(), findings, req.MaxItems)
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	jsonOK(w, result)
}

// POST /api/v1/ti/secret/check — check if a secret is still valid
func (h *ThreatIntel) CheckSecret(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value string `json:"value"`
		Type  string `json:"type"` // optional, auto-detect if empty
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Value == "" {
		jsonError(w, "value required", http.StatusBadRequest)
		return
	}
	checker := secretcheck.NewChecker()
	stype := secretcheck.DetectType(req.Value)
	if req.Type != "" {
		stype = secretcheck.SecretType(req.Type)
	}
	result := checker.Check(r.Context(), stype, req.Value)
	jsonOK(w, result)
}

// POST /api/v1/ti/secret/check/batch — check multiple secrets from findings
func (h *ThreatIntel) CheckSecretBatch(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Load gitleaks findings
	findings, _, err := h.DB.ListFindings(r.Context(), claims.TenantID, store.FindingFilter{
		Limit: 100,
	})
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	checker := secretcheck.NewChecker()
	type result struct {
		FindingID  string                      `json:"finding_id"`
		Tool       string                      `json:"tool"`
		RuleID     string                      `json:"rule_id"`
		Validity   *secretcheck.SecretValidity `json:"validity"`
	}
	var results []result
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.Tool != "gitleaks" { continue }
		if seen[f.RuleID] { continue }
		seen[f.RuleID] = true
		stype := secretcheck.DetectType(f.FixSignal)
		if stype == secretcheck.SecretGeneric { continue } // skip undetectable
		v := checker.Check(r.Context(), stype, f.FixSignal)
		results = append(results, result{
			FindingID: f.ID, Tool: f.Tool,
			RuleID: f.RuleID, Validity: v,
		})
	}
	if results == nil { results = []result{} }
	jsonOK(w, map[string]any{"results": results, "total": len(results)})
}

// GET /api/v1/compliance/license — scan license compliance
func (h *ThreatIntel) LicenseCompliance(w http.ResponseWriter, r *http.Request) {
	_, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Scan VSP project itself
	projectPath := "/home/test/Data/GOLANG_VSP"
	sc := licenseScanner.NewScanner(licenseScanner.DefaultPolicy)
	result, err := sc.Scan(projectPath)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, result)
}
