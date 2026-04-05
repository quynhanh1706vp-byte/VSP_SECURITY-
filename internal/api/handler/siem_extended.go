package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/viper"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/siem"
	"github.com/vsp/platform/internal/store"
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
	if req.WindowMin == 0 { req.WindowMin = 5 }
	if req.Severity == ""  { req.Severity = "HIGH" }
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

	// Parse steps
	var rawSteps []map[string]string
	if err := json.Unmarshal(stepsRaw, &rawSteps); err != nil { log.Warn().Err(err).Caller().Msg("ignored error") }
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
	go siem.ExecutePlaybook(context.Background(), h.DB, runID, rawSteps, rc)

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
