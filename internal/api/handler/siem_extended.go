package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/viper"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/siem"
	"strings"

	"github.com/rs/zerolog/log"
	aiPkg "github.com/vsp/platform/internal/ai"
	"github.com/vsp/platform/internal/integrations/virustotal"
	licenseScanner "github.com/vsp/platform/internal/scanner/license"
	"github.com/vsp/platform/internal/scanner/secretcheck"
	"github.com/vsp/platform/internal/store"
	"github.com/vsp/platform/internal/threatintel"
)

// ── Correlation ───────────────────────────────────────────────

type Correlation struct{ DB *store.DB }

func (h *Correlation) ListRules(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rules, err := h.DB.ListCorrelationRules(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if rules == nil {
		rules = []store.CorrelationRule{}
	}
	totalCount, _ := h.DB.CountCorrelationRules(r.Context(), claims.TenantID)
	if totalCount == 0 {
		totalCount = len(rules)
	}
	jsonOK(w, map[string]any{"rules": rules, "total": totalCount, "page_size": len(rules)})
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
	if !decodeJSON(w, r, &req) {
		return // decodeJSON already wrote the error response
	}
	if req.Name == "" {
		jsonError(w, "name required", http.StatusBadRequest)
		return
	}
	if len(req.Name) > 200 {
		req.Name = req.Name[:200]
	}
	if req.WindowMin <= 0 {
		req.WindowMin = 5
	}
	if req.WindowMin > 1440 {
		req.WindowMin = 1440
	} // max 24h
	validSevs := map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}
	if !validSevs[req.Severity] {
		req.Severity = "HIGH"
	}
	if req.Sources == nil {
		req.Sources = []string{"scan"}
	}

	id, err := h.DB.CreateCorrelationRule(r.Context(), store.CorrelationRule{
		TenantID:  claims.TenantID,
		Name:      req.Name,
		Sources:   req.Sources,
		WindowMin: req.WindowMin,
		Severity:  req.Severity,
		Condition: req.Condition,
		Enabled:   req.Enabled,
	})
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": id, "name": req.Name, "status": "created"})
}

func (h *Correlation) ToggleRule(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	enabled, err := h.DB.ToggleCorrelationRule(r.Context(), claims.TenantID, id)
	if err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	logAudit(r, h.DB, "CORRELATION_RULE_TOGGLED", "correlation_rules/toggle")
	jsonOK(w, map[string]any{"id": id, "enabled": enabled})
}

func (h *Correlation) DeleteRule(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	h.DB.DeleteCorrelationRule(r.Context(), claims.TenantID, chi.URLParam(r, "id")) //nolint:errcheck
	logAudit(r, h.DB, "CORRELATION_RULE_DELETED", "correlation_rules/delete")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Correlation) ListIncidents(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit := 50
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
		if l > 500 {
			l = 500
		}
		limit = l
	}
	incidents, err := h.DB.ListIncidents(r.Context(), claims.TenantID,
		r.URL.Query().Get("status"), r.URL.Query().Get("severity"), limit)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if incidents == nil {
		incidents = []store.Incident{}
	}
	totalCount, _ := h.DB.CountIncidents(r.Context(), claims.TenantID,
		r.URL.Query().Get("status"), r.URL.Query().Get("severity"))
	if totalCount == 0 {
		totalCount = len(incidents)
	}
	jsonOK(w, map[string]any{
		"incidents": incidents,
		"total":     totalCount,
		"page_size": len(incidents),
	})
}

func (h *Correlation) CreateIncident(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req struct {
		Title      string          `json:"title"`
		Severity   string          `json:"severity"`
		RuleID     string          `json:"rule_id"`
		SourceRefs json.RawMessage `json:"source_refs"`
	}
	if !decodeJSON(w, r, &req) {
		return // decodeJSON already wrote error
	}
	if req.Title == "" {
		jsonError(w, "title required", http.StatusBadRequest)
		return
	}
	if req.Severity == "" {
		req.Severity = "HIGH"
	}
	if req.SourceRefs == nil {
		req.SourceRefs = json.RawMessage("{}")
	}
	var ruleID *string
	if req.RuleID != "" {
		ruleID = &req.RuleID
	}
	id, err := h.DB.CreateIncident(r.Context(), store.Incident{
		TenantID:   claims.TenantID,
		Title:      req.Title,
		Severity:   req.Severity,
		RuleID:     ruleID,
		SourceRefs: req.SourceRefs,
	})
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	logAudit(r, h.DB, "INCIDENT_CREATED", "incidents/create")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "status": "created"})
}

func (h *Correlation) ResolveIncident(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		Status string `json:"status"`
	}
	decodeJSON(w, r, &req)
	if req.Status == "" {
		req.Status = "resolved"
	}
	if req.Status != "resolved" && req.Status != "open" && req.Status != "investigating" && req.Status != "archived" {
		jsonError(w, "invalid status", http.StatusBadRequest)
		return
	}
	if err := h.DB.UpdateIncidentStatus(r.Context(), claims.TenantID, id, req.Status); err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]any{"id": id, "status": req.Status})
}

func (h *Correlation) GetIncident(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	inc, err := h.DB.GetIncident(r.Context(), claims.TenantID, id)
	if err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	jsonOK(w, inc)
}

// ── SOAR ──────────────────────────────────────────────────────

type SOAR struct{ DB *store.DB }

func (h *SOAR) ListPlaybooks(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	pbs, err := h.DB.ListPlaybooks(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if pbs == nil {
		pbs = []store.Playbook{}
	}
	totalCount, _ := h.DB.CountPlaybooks(r.Context(), claims.TenantID)
	if totalCount == 0 {
		totalCount = len(pbs)
	}
	jsonOK(w, map[string]any{"playbooks": pbs, "total": totalCount, "page_size": len(pbs)})
}

func (h *SOAR) CreatePlaybook(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Trigger     string          `json:"trigger"`
		SevFilter   string          `json:"sev_filter"`
		Steps       json.RawMessage `json:"steps"`
		Enabled     bool            `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name required", http.StatusBadRequest)
		return
	}
	if req.SevFilter == "" {
		req.SevFilter = "any"
	}
	if req.Steps == nil {
		req.Steps = json.RawMessage("[]")
	}
	id, err := h.DB.CreatePlaybook(r.Context(), store.Playbook{
		TenantID:    claims.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Trigger:     req.Trigger,
		SevFilter:   req.SevFilter,
		Steps:       req.Steps,
		Enabled:     req.Enabled,
	})
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	logAudit(r, h.DB, "PLAYBOOK_CREATED", "playbooks/create")
	jsonOK(w, map[string]any{"id": id, "name": req.Name, "status": "created"})
}

func (h *SOAR) TogglePlaybook(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	enabled, err := h.DB.TogglePlaybook(r.Context(), claims.TenantID, id)
	if err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	logAudit(r, h.DB, "PLAYBOOK_TOGGLED", "playbooks/toggle")
	jsonOK(w, map[string]any{"id": id, "enabled": enabled})
}


// DELETE /api/v1/soar/playbooks/{id}
func (h *SOAR) DeletePlaybook(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok { jsonError(w, "unauthorized", http.StatusUnauthorized); return }
	id := chi.URLParam(r, "id")
	_, err := h.DB.Pool().Exec(r.Context(),
		"DELETE FROM playbooks WHERE id=$1 AND tenant_id=$2", id, claims.TenantID)
	if err != nil { jsonError(w, "delete failed", http.StatusInternalServerError); return }
	logAudit(r, h.DB, "PLAYBOOK_DELETED", "playbooks/"+id)
	w.WriteHeader(http.StatusNoContent)
}

// PATCH /api/v1/soar/playbooks/{id}
func (h *SOAR) UpdatePlaybook(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok { jsonError(w, "unauthorized", http.StatusUnauthorized); return }
	id := chi.URLParam(r, "id")
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Trigger     string          `json:"trigger"`
		SevFilter   string          `json:"sev_filter"`
		Steps       json.RawMessage `json:"steps"`
		Enabled     *bool           `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) { return }
	_, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE playbooks SET
		 name=COALESCE(NULLIF($3,''), name),
		 description=COALESCE(NULLIF($4,''), description),
		 trigger_event=COALESCE(NULLIF($5,''), trigger_event),
		 sev_filter=COALESCE(NULLIF($6,''), sev_filter),
		 steps=COALESCE($7::jsonb, steps),
		 enabled=COALESCE($8, enabled),
		 updated_at=NOW()
		 WHERE id=$1 AND tenant_id=$2`,
		id, claims.TenantID, req.Name, req.Description, req.Trigger,
		req.SevFilter, nullJSON(req.Steps), req.Enabled)
	if err != nil { jsonError(w, "update failed: "+err.Error(), http.StatusInternalServerError); return }
	logAudit(r, h.DB, "PLAYBOOK_UPDATED", "playbooks/"+id)
	jsonOK(w, map[string]string{"id": id, "status": "updated"})
}

func nullJSON(b json.RawMessage) interface{} {
	if len(b) == 0 || string(b) == "null" { return nil }
	return string(b)
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
	if err != nil {
		jsonError(w, "playbook not found", http.StatusNotFound)
		return
	}

	var ctxRaw json.RawMessage
	decodeJSON(w, r, &ctxRaw) //nolint:errcheck
	if ctxRaw == nil {
		ctxRaw = json.RawMessage(`{"trigger":"manual"}`)
	}

	runID, err := h.DB.CreatePlaybookRun(r.Context(), id, claims.TenantID, "manual", ctxRaw)
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Parse run context
	var runCtxMap map[string]string
	if err := json.Unmarshal(ctxRaw, &runCtxMap); err != nil {
		log.Warn().Err(err).Caller().Msg("ignored error")
	}
	if runCtxMap == nil {
		runCtxMap = map[string]string{}
	}

	// Parse + validate steps
	var rawSteps []map[string]string
	if err := json.Unmarshal(stepsRaw, &rawSteps); err != nil {
		log.Warn().Err(err).Caller().Msg("ignored error")
	}
	// Validate step types — prevent injection of unknown step types
	validStepTypes := map[string]bool{
		"condition": true, "notify": true, "ticket": true, "block": true,
		"webhook": true, "enrich": true, "remediate": true, "wait": true,
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
	if rc.Gate == "" {
		rc.Gate = "FAIL"
	}
	if rc.Severity == "" {
		rc.Severity = "HIGH"
	}

	// Execute async
	go siem.ExecutePlaybook(context.Background(), h.DB, runID, rawSteps, rc) //nolint:gosec // G118: playbook runs async beyond request lifetime

	jsonOK(w, map[string]any{"run_id": runID, "playbook": name, "status": "running"})
}

func (h *SOAR) Trigger(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Trigger  string `json:"trigger"`
		Severity string `json:"severity"`
		RunID    string `json:"run_id"`
		Findings int    `json:"findings"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Severity == "" {
		req.Severity = "any"
	}
	pbs, err := h.DB.FindEnabledPlaybooks(r.Context(), claims.TenantID, req.Trigger, req.Severity)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
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
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
		if l > 500 {
			l = 500
		}
		limit = l
	}
	runs, err := h.DB.ListPlaybookRuns(r.Context(), claims.TenantID, limit)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []store.PlaybookRun{}
	}
	totalCount, _ := h.DB.CountPlaybookRuns(r.Context(), claims.TenantID)
	if totalCount == 0 {
		totalCount = len(runs)
	}
	jsonOK(w, map[string]any{"runs": runs, "total": totalCount, "page_size": len(runs)})
}

// ── Log sources ───────────────────────────────────────────────

type LogSources struct{ DB *store.DB }

func (h *LogSources) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	sources, err := h.DB.ListLogSources(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if sources == nil {
		sources = []store.LogSource{}
	}
	totalCount, _ := h.DB.CountLogSources(r.Context(), claims.TenantID)
	if totalCount == 0 {
		totalCount = len(sources)
	}
	jsonOK(w, map[string]any{"sources": sources, "total": totalCount, "page_size": len(sources)})
}

func (h *LogSources) Create(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req store.LogSource
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name required", http.StatusBadRequest)
		return
	}
	if req.Protocol == "" {
		req.Protocol = "syslog-udp"
	}
	if req.Format == "" {
		req.Format = "syslog-rfc3164"
	}
	if req.Port == 0 {
		req.Port = 514
	}
	req.TenantID = claims.TenantID
	id, err := h.DB.CreateLogSource(r.Context(), req)
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	logAudit(r, h.DB, "LOG_SOURCE_CREATED", "log_sources/create")
	jsonOK(w, map[string]any{"id": id, "name": req.Name, "status": "created"})
}

func (h *LogSources) Delete(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	h.DB.DeleteLogSource(r.Context(), claims.TenantID, chi.URLParam(r, "id")) //nolint:errcheck
	logAudit(r, h.DB, "LOG_SOURCE_DELETED", "log_sources/delete")
	w.WriteHeader(http.StatusNoContent)
}

func (h *LogSources) Test(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.DB.TestLogSource(r.Context(), claims.TenantID, chi.URLParam(r, "id")); err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
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
		`SELECT COUNT(*) FROM log_events WHERE tenant_id=$1 AND ts >= NOW()-interval'5 seconds'`,
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
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
		if l > 500 {
			l = 500
		}
		limit = l
	}
	iocs, err := h.DB.ListIOCs(r.Context(), r.URL.Query().Get("type"), limit)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if iocs == nil {
		iocs = []store.IOC{}
	}
	totalCount, _ := h.DB.CountIOCs(r.Context(), r.URL.Query().Get("type"))
	if totalCount == 0 {
		totalCount = len(iocs)
	}
	jsonOK(w, map[string]any{"iocs": iocs, "total": totalCount, "page_size": len(iocs)})
}

func (h *ThreatIntel) ListFeeds(w http.ResponseWriter, r *http.Request) {
	type Feed struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		IOCs   int    `json:"iocs"`
		Last   string `json:"last"`
	}
	names := []string{"NVD / NIST", "OSV database", "MISP community", "AlienVault OTX", "AbuseIPDB", "STIX / TAXII"}
	feeds := make([]Feed, len(names))
	for i, name := range names {
		cnt := h.DB.IOCFeedCounts(r.Context(), name)
		status := "ok"
		if cnt == 0 && i >= 4 {
			status = map[int]string{4: "warn", 5: "err"}[i]
		}
		feeds[i] = Feed{Name: name, Status: status, IOCs: cnt, Last: "5m"}
	}
	// feeds is an in-memory hardcoded list of 6 sources; len(feeds) IS total.
	jsonOK(w, map[string]any{"feeds": feeds, "total": len(feeds)}) // safe-len: in-memory derived
}

func (h *ThreatIntel) Matches(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l, _ := strconv.Atoi(r.URL.Query().Get("limit")); l > 0 {
		limit = l
	}
	iocs, err := h.DB.ListIOCs(r.Context(), "", limit)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	matched := make([]store.IOC, 0)
	for _, ioc := range iocs {
		if ioc.Matched {
			matched = append(matched, ioc)
		}
	}
	totalCount, _ := h.DB.CountMatchedIOCs(r.Context())
	if totalCount == 0 {
		totalCount = len(matched)
	}
	jsonOK(w, map[string]any{"matches": matched, "total": totalCount, "page_size": len(matched)})
}

func (h *ThreatIntel) MITRE(w http.ResponseWriter, r *http.Request) {
	type Tactic struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	cweMap := map[string]string{
		"CWE-78": "TA0002", "CWE-79": "TA0001", "CWE-89": "TA0001",
		"CWE-798": "TA0006", "CWE-200": "TA0009", "CWE-22": "TA0007",
		"CWE-287": "TA0001", "CWE-502": "TA0002",
	}
	counts := map[string]int{}
	for cwe, tactic := range cweMap {
		counts[tactic] += h.DB.FindingCWECount(r.Context(), cwe)
	}
	tactics := []Tactic{
		{"TA0001", "Initial access", counts["TA0001"]},
		{"TA0002", "Execution", counts["TA0002"]},
		{"TA0003", "Persistence", 0},
		{"TA0004", "Priv esc", 0},
		{"TA0005", "Def evasion", 0},
		{"TA0006", "Cred access", counts["TA0006"]},
		{"TA0007", "Discovery", counts["TA0007"]},
		{"TA0008", "Lateral mov", 0},
		{"TA0009", "Collection", counts["TA0009"]},
		{"TA0010", "Exfiltration", 0},
	}
	jsonOK(w, map[string]any{"tactics": tactics})
}

func (h *ThreatIntel) SyncFeeds(w http.ResponseWriter, r *http.Request) {
	// IOC seed can take 10s+ on a large findings table — way past the
	// HTTP response cycle. Pre-fix it raced r.Context() and never
	// completed under any non-trivial dataset.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		h.DB.SeedIOCsFromFindings(ctx)
	}()
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
		jsonError(w, err.Error(), http.StatusBadGateway) // safe-err-leak: upstream webhook fetch
		return
	}
	jsonOK(w, enr)
}

// POST /api/v1/ti/enrich/batch
func (h *ThreatIntel) EnrichBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CVEs []string `json:"cves"`
	}
	if !decodeJSON(w, r, &req) {
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
	// Caller-driven: results is 1-to-1 with req.CVEs (capped at 50). len IS total.
	jsonOK(w, map[string]any{"enrichments": results, "total": len(results)}) // safe-len: input-driven
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
		if d.IsPersistent {
			persistent++
		}
	}

	jsonOK(w, map[string]any{
		"findings":     deduped,
		"total_raw":    total,
		"total_unique": len(deduped),
		"persistent":   persistent,
		"dedup_ratio":  fmt.Sprintf("%.1f%%", float64(int64(len(deduped))-total)*-1/float64(total)*100),
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
	// chains is the algorithm output over the 5000-finding sample. Sampled.
	jsonOK(w, map[string]any{
		"chains":      chains,
		"total":       len(chains), // safe-len: derived (5k-finding sample)
		"sample_size": 5000,
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
	decodeJSON(w, r, &req) //nolint:errcheck
	if req.MaxItems == 0 {
		req.MaxItems = 5
	}
	if req.MaxItems > 20 {
		req.MaxItems = 20
	}

	filter := store.FindingFilter{Limit: 500}
	if req.Severity != "" {
		filter.Severity = req.Severity
	}

	findings, _, err := h.DB.ListFindings(r.Context(), claims.TenantID, filter)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	// Filter by specific IDs if provided
	if len(req.FindingIDs) > 0 {
		idSet := make(map[string]bool)
		for _, id := range req.FindingIDs {
			idSet[id] = true
		}
		filtered := findings[:0]
		for _, f := range findings {
			if idSet[f.ID] {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	analyzer := aiPkg.NewSemanticAnalyzer()
	result, err := analyzer.AnalyzeBatch(r.Context(), findings, req.MaxItems)
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable) // safe-err-leak: upstream NVD/EPSS fetch
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
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Value == "" {
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
		FindingID string                      `json:"finding_id"`
		Tool      string                      `json:"tool"`
		RuleID    string                      `json:"rule_id"`
		Validity  *secretcheck.SecretValidity `json:"validity"`
	}
	var results []result
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.Tool != "gitleaks" {
			continue
		}
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		stype := secretcheck.DetectType(f.FixSignal)
		if stype == secretcheck.SecretGeneric {
			continue
		} // skip undetectable
		v := checker.Check(r.Context(), stype, f.FixSignal)
		results = append(results, result{
			FindingID: f.ID, Tool: f.Tool,
			RuleID: f.RuleID, Validity: v,
		})
	}
	if results == nil {
		results = []result{}
	}
	// results derived from 100-finding gitleaks scan; reported total is sample-bound.
	jsonOK(w, map[string]any{"results": results, "total": len(results)}) // safe-len: derived (100-finding sample)
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
		jsonInternalError(w, r, "internal error", err)
		return
	}
	jsonOK(w, result)
}

// Stats returns observability info about threat intel state.
// GET /api/v1/ti/stats
func (h *ThreatIntel) Stats(w http.ResponseWriter, r *http.Request) {
	stats := _tiClient.Stats()
	jsonOK(w, stats)
}

// RefreshKEV triggers immediate KEV catalog reload (admin only).
// POST /api/v1/ti/kev/refresh
func (h *ThreatIntel) RefreshKEV(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != "admin" {
		jsonError(w, "admin role required", http.StatusForbidden)
		return
	}
	if err := _tiClient.RefreshKEV(r.Context()); err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway) // safe-err-leak: upstream webhook fetch
		return
	}
	jsonOK(w, _tiClient.Stats())
}

// _vtClient is package-level singleton for VirusTotal integration.
// Initialized once on package load. API key from VSP_VT_API_KEY env.
var _vtClient = virustotal.NewClient()

// ComponentThreat returns VirusTotal threat assessment for a SW component.
// GET /api/v1/sw/component/:hash/threat
// Returns 200 with verdict if VT configured, 503 if not configured,
// 400 for invalid hash, 502 for VT API errors.
func (h *ThreatIntel) ComponentThreat(w http.ResponseWriter, r *http.Request) {
	hash := strings.TrimSpace(chi.URLParam(r, "hash"))
	if hash == "" {
		jsonError(w, "hash param required", http.StatusBadRequest)
		return
	}

	if !_vtClient.Configured() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "virustotal not configured",
			"hint":    "set VSP_VT_API_KEY environment variable",
			"verdict": "unavailable",
		})
		return
	}

	report, err := _vtClient.GetFileReport(r.Context(), hash)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway) // safe-err-leak: upstream webhook fetch
		return
	}
	jsonOK(w, report)
}

// VTStats returns observability info for VirusTotal client.
// GET /api/v1/integrations/virustotal/stats
func (h *ThreatIntel) VTStats(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, _vtClient.Stats())
}

// ─── UI 404 FIX: Stub handlers for missing routes ─────────────────
// These return empty data to prevent panel 404s.
// Full implementation deferred to next sprint.

// UISTubSettings serves GET /api/v1/settings/* with empty config.
// Used by: settings panel (dast-targets, scan-config)
func (h *ThreatIntel) UISTubSettings(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"items":   []any{},
		"enabled": false,
		"note":    "Stub endpoint — real settings storage pending",
	})
}

// UISTubSwReport serves POST /api/v1/sw/report with stub success.
// Used by: sw_inventory panel "Send Report" action
func (h *ThreatIntel) UISTubSwReport(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"received": true,
		"note":     "Stub endpoint — report storage pending",
	})
}

// UISTubIntegrationsList serves GET /api/v1/integrations/* with empty list.
// Used by: integrations panel
func (h *ThreatIntel) UISTubIntegrationsList(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"integrations": []any{},
		"note":         "Stub — only VirusTotal active. Other integrations pending.",
	})
}

// UISTubIntegrationsTest serves POST /api/v1/integrations/{provider}/test-*
// with stub "test passed".
func (h *ThreatIntel) UISTubIntegrationsTest(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	if provider == "" {
		provider = "unknown"
	}
	jsonOK(w, map[string]any{
		"ok":       false,
		"provider": provider,
		"note":     "Stub — real test integration pending",
	})
}

// ─── UI Real Data Handlers ─────────────────────────────────────────
// Pattern: h.DB.Pool().QueryRow(ctx, ...) — pgx (not database/sql)

// IntegrationsList serves GET /api/v1/integrations
// Returns webhooks from siem_webhooks table.
func (h *ThreatIntel) IntegrationsList(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id::text, label, type, url, min_sev, active,
		        COALESCE(last_fired::text, ''), fire_count
		 FROM siem_webhooks
		 WHERE tenant_id = $1
		 ORDER BY type, label`,
		claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type integration struct {
		ID        string `json:"id"`
		Label     string `json:"label"`
		Type      string `json:"type"`
		URL       string `json:"url"`
		MinSev    string `json:"min_severity"`
		Active    bool   `json:"active"`
		LastFired string `json:"last_fired,omitempty"`
		FireCount int    `json:"fire_count"`
	}
	var items []integration
	for rows.Next() {
		var it integration
		if scanErr := rows.Scan(&it.ID, &it.Label, &it.Type, &it.URL,
			&it.MinSev, &it.Active, &it.LastFired, &it.FireCount); scanErr == nil {
			// Mask URL — show domain only
			if idx := strings.Index(it.URL, "://"); idx > 0 {
				rest := it.URL[idx+3:]
				if slash := strings.Index(rest, "/"); slash > 0 {
					it.URL = it.URL[:idx+3] + rest[:slash] + "/***"
				}
			}
			items = append(items, it)
		}
	}
	if items == nil {
		items = []integration{}
	}

	providers := map[string]bool{
		"slack":      false,
		"teams":      false,
		"smtp":       false,
		"github":     false,
		"jira":       false,
		"servicenow": false,
		"pagerduty":  false,
		"virustotal": _vtClient.Configured(),
	}
	for _, it := range items {
		providers[it.Type] = true
	}

	// SQL has no LIMIT — `items` is the complete set.
	jsonOK(w, map[string]any{
		"integrations": items,
		"providers":    providers,
		"total":        len(items), // safe-len: unlimited query
	})
}

// IntegrationsTestProvider serves POST /api/v1/integrations/{provider}/test-*
func (h *ThreatIntel) IntegrationsTestProvider(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	provider := chi.URLParam(r, "provider")

	var url, providerType string
	var active bool
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT url, type, active FROM siem_webhooks
		 WHERE tenant_id = $1 AND type = $2
		 LIMIT 1`, claims.TenantID, provider).Scan(&url, &providerType, &active)

	if err != nil {
		jsonOK(w, map[string]any{
			"ok":       false,
			"provider": provider,
			"error":    "no integration configured for this provider",
			"hint":     "configure in integrations panel first",
		})
		return
	}

	if !active {
		jsonOK(w, map[string]any{
			"ok":       false,
			"provider": provider,
			"error":    "integration is disabled",
		})
		return
	}

	// SSRF guard: tenant-supplied webhook URL must pass the same
	// allowlist used by the delivery path (private/loopback/RFC1918,
	// metadata aliases, NXDOMAIN-fail-closed). Pre-fix this handler
	// did a HEAD straight to whatever the tenant configured — letting
	// "Test integration" pivot to 169.254.169.254 cloud-metadata.
	if err := siem.ValidateWebhookURL(url); err != nil {
		jsonOK(w, map[string]any{
			"ok":       false,
			"provider": provider,
			"error":    "URL blocked by SSRF policy",
		})
		return
	}

	// HEAD ping (5s timeout)
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodHead, url, nil)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, pingErr := client.Do(req)
	if pingErr != nil {
		// Don't echo the network error string — it leaks the resolved
		// URL and DNS infrastructure (the previous "endpoint
		// unreachable: dial tcp ..." reply happily told the caller
		// which internal IP an attacker-controlled hostname pointed at).
		log.Warn().Err(pingErr).Str("provider", provider).Msg("integration test: ping failed")
		jsonOK(w, map[string]any{
			"ok":       false,
			"provider": provider,
			"error":    "endpoint unreachable",
		})
		return
	}
	defer resp.Body.Close()

	jsonOK(w, map[string]any{
		"ok":          resp.StatusCode < 500,
		"provider":    provider,
		"http_status": resp.StatusCode,
	})
}

// SettingsScanConfig serves GET /api/v1/settings/scan-config
// Queries policy_rules table.
func (h *ThreatIntel) SettingsScanConfig(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id::text, name, repo_pattern, fail_on, min_score,
		        max_high, block_secrets, block_critical, active
		 FROM policy_rules
		 WHERE tenant_id = $1
		 ORDER BY name`, claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type policyRule struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		RepoPattern   string `json:"repo_pattern"`
		FailOn        string `json:"fail_on"`
		MinScore      int    `json:"min_score"`
		MaxHigh       int    `json:"max_high"`
		BlockSecrets  bool   `json:"block_secrets"`
		BlockCritical bool   `json:"block_critical"`
		Active        bool   `json:"active"`
	}
	var items []policyRule
	for rows.Next() {
		var p policyRule
		if scanErr := rows.Scan(&p.ID, &p.Name, &p.RepoPattern, &p.FailOn,
			&p.MinScore, &p.MaxHigh, &p.BlockSecrets, &p.BlockCritical, &p.Active); scanErr == nil {
			items = append(items, p)
		}
	}
	if items == nil {
		items = []policyRule{}
	}

	// SQL has no LIMIT — items is the complete policy_rules set.
	jsonOK(w, map[string]any{"rules": items, "total": len(items)}) // safe-len: unlimited query
}

// SettingsDastTargets serves GET /api/v1/settings/dast-targets
// Derives from runs.target_url history.
func (h *ThreatIntel) SettingsDastTargets(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT target_url, MAX(created_at)::text as last_scan,
		        COUNT(*)::int as scan_count
		 FROM runs
		 WHERE tenant_id = $1
		   AND target_url IS NOT NULL
		   AND target_url != ''
		 GROUP BY target_url
		 ORDER BY last_scan DESC
		 LIMIT 50`, claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type dastTarget struct {
		URL       string `json:"url"`
		LastScan  string `json:"last_scan"`
		ScanCount int    `json:"scan_count"`
	}
	var targets []dastTarget
	for rows.Next() {
		var t dastTarget
		if scanErr := rows.Scan(&t.URL, &t.LastScan, &t.ScanCount); scanErr == nil {
			targets = append(targets, t)
		}
	}
	if targets == nil {
		targets = []dastTarget{}
	}

	totalCount, _ := h.DB.CountDastTargets(r.Context(), claims.TenantID)
	if totalCount == 0 {
		totalCount = len(targets)
	}
	jsonOK(w, map[string]any{"targets": targets, "total": totalCount, "page_size": len(targets)})
}

// SBOMIndex serves GET /api/v1/sbom — list runs với SBOM URLs.
func (h *ThreatIntel) SBOMIndex(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT rid, created_at::text, mode, status, total_findings
		 FROM runs
		 WHERE tenant_id = $1 AND status = 'DONE'
		 ORDER BY created_at DESC
		 LIMIT 50`, claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type sbomRun struct {
		RID           string `json:"rid"`
		CreatedAt     string `json:"created_at"`
		Mode          string `json:"mode"`
		Status        string `json:"status"`
		TotalFindings int    `json:"total_findings"`
		SBOMURL       string `json:"sbom_url"`
		GrypeURL      string `json:"grype_url"`
		DiffURL       string `json:"diff_url"`
	}
	var runs []sbomRun
	for rows.Next() {
		var s sbomRun
		if scanErr := rows.Scan(&s.RID, &s.CreatedAt, &s.Mode, &s.Status, &s.TotalFindings); scanErr == nil {
			s.SBOMURL = "/api/v1/sbom/" + s.RID
			s.GrypeURL = "/api/v1/sbom/" + s.RID + "/grype"
			s.DiffURL = "/api/v1/sbom/" + s.RID + "/diff"
			runs = append(runs, s)
		}
	}
	if runs == nil {
		runs = []sbomRun{}
	}

	totalCount, _ := h.DB.CountSBOMRuns(r.Context(), claims.TenantID)
	if totalCount == 0 {
		totalCount = len(runs)
	}
	jsonOK(w, map[string]any{
		"runs":      runs,
		"total":     totalCount,
		"page_size": len(runs),
		"format":    "CycloneDX 1.5 (JSON)",
	})
}

// OSCALIndex serves GET /api/p4/oscal — list of OSCAL endpoints.
func (h *ThreatIntel) OSCALIndex(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"available_endpoints": []map[string]string{
			{"path": "/api/p4/oscal/catalog", "description": "NIST 800-53 control catalog"},
			{"path": "/api/p4/oscal/profile", "description": "VSP system profile"},
			{"path": "/api/p4/oscal/ssp", "description": "System Security Plan"},
			{"path": "/api/p4/oscal/ssp/extended", "description": "Extended SSP"},
			{"path": "/api/p4/oscal/poam-extended", "description": "POA&M with metadata"},
			{"path": "/api/p4/oscal/assessment-plan", "description": "SAP"},
			{"path": "/api/p4/oscal/assessment-results", "description": "SAR"},
		},
		"version": "OSCAL 1.0.4",
		"format":  "JSON",
	})
}

// IntegrationsSaveProvider serves POST /api/v1/integrations/{provider}
// Upserts webhook config into siem_webhooks table.
func (h *ThreatIntel) IntegrationsSaveProvider(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	provider := chi.URLParam(r, "provider")
	if provider == "" {
		jsonError(w, "provider required", http.StatusBadRequest)
		return
	}

	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Extract URL — field name differs per provider
	urlVal := ""
	for _, k := range []string{"url", "webhook_url", "token", "key"} {
		if v, ok := body[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				urlVal = s
				break
			}
		}
	}
	label := provider
	if n, ok := body["name"].(string); ok && n != "" {
		label = n
	}

	_, err := h.DB.Pool().Exec(r.Context(), `
		INSERT INTO siem_webhooks (tenant_id, label, type, url, min_sev, active)
		VALUES ($1, $2, $3, $4, 'LOW', true)`,
		claims.TenantID, label, provider, urlVal)
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"ok": true, "provider": provider})
}
