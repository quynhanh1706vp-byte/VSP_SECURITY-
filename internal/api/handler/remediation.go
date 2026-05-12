package handler

import (
	"github.com/rs/zerolog/log"
	"net/http"
	"sync"
	"time"

	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
	"strings"
)

type Remediation struct{ DB *store.DB }

// remStatsCache memoises /remediation/stats per tenant for 30s.
// Why: the dashboard ticker polls this endpoint every 30s per logged-in
// browser tab. A tenant with 55k+ remediations was tripping the FE's
// 8s safeApi timeout under load — the GROUP BY query is fast (idx_rem_
// tenant covers it) but contended with concurrent scan-writes. Memoising
// in BE means each poll cycle issues one DB query at most, regardless of
// how many UI tabs are open, and the second-through-Nth tab gets a
// sub-millisecond response.
var remStatsCache sync.Map // tenantID -> *remStatsEntry

type remStatsEntry struct {
	at   time.Time
	data map[string]int
}

const remStatsTTL = 30 * time.Second

// GET /api/v1/remediation — list all with optional ?status=open
func (h *Remediation) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	status := r.URL.Query().Get("status")
	list, err := h.DB.ListRemediations(r.Context(), claims.TenantID, status)
	if err != nil {
		log.Error().Err(err).Str("tenant", claims.TenantID).Msg("ListRemediations failed")
		jsonInternalError(w, r, "db error", err)
		return
	}
	if list == nil {
		list = []store.Remediation{}
	}
	totalCount, _ := h.DB.CountRemediations(r.Context(), claims.TenantID, status)
	if totalCount == 0 {
		totalCount = len(list)
	}
	jsonOK(w, map[string]any{
		"remediations": list,
		"total":        totalCount,
		"page_size":    len(list),
	})
}

// GET /api/v1/remediation/stats
func (h *Remediation) Stats(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	// Cache hit?
	if v, ok := remStatsCache.Load(claims.TenantID); ok {
		ent := v.(*remStatsEntry)
		if time.Since(ent.at) < remStatsTTL {
			jsonOK(w, ent.data)
			return
		}
	}
	stats, err := h.DB.RemediationStats(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	remStatsCache.Store(claims.TenantID, &remStatsEntry{at: time.Now(), data: stats})
	jsonOK(w, stats)
}

// GET /api/v1/remediation/finding/{finding_id}
func (h *Remediation) Get(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	fid := chi.URLParam(r, "finding_id")
	if !validateUUID(fid) {
		jsonError(w, "invalid finding_id", http.StatusBadRequest)
		return
	}
	rem, err := h.DB.GetRemediation(r.Context(), claims.TenantID, fid)
	if err != nil {
		jsonOK(w, map[string]any{"status": "open", "finding_id": fid})
		return
	}
	// Also load comments
	comments, _ := h.DB.ListComments(r.Context(), rem.ID)
	if comments == nil {
		comments = []store.RemediationComment{}
	}
	jsonOK(w, map[string]any{"remediation": rem, "comments": comments})
}

// POST /api/v1/remediation/finding/{finding_id}
func (h *Remediation) Upsert(w http.ResponseWriter, r *http.Request) {
	defer logAudit(r, h.DB, "REMEDIATION_UPDATED", "/remediation/"+chi.URLParam(r, "finding_id"))
	claims, _ := auth.FromContext(r.Context())
	fid := chi.URLParam(r, "finding_id")
	var req struct {
		Status    string `json:"status"`
		Assignee  string `json:"assignee"`
		Priority  string `json:"priority"`
		Notes     string `json:"notes"`
		TicketURL string `json:"ticket_url"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Status == "" {
		req.Status = "open"
	}
	if req.Priority == "" {
		req.Priority = "P3"
	}
	// Validate TicketURL — chặn SSRF + chỉ cho phép http/https
	if req.TicketURL != "" {
		if err := validateScanURL(req.TicketURL); err != nil {
			jsonError(w, "invalid ticket_url: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	rem, err := h.DB.UpsertRemediation(r.Context(), store.Remediation{
		FindingID: fid,
		TenantID:  claims.TenantID,
		Status:    store.RemediationStatus(req.Status),
		Assignee:  req.Assignee,
		Priority:  req.Priority,
		Notes:     req.Notes,
		TicketURL: req.TicketURL,
	})
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, rem)
}

// POST /api/v1/remediation/{rem_id}/comments
func (h *Remediation) AddComment(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	remID := chi.URLParam(r, "rem_id")
	var req struct {
		Body string `json:"body"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Body == "" {
		jsonError(w, "body required", http.StatusBadRequest)
		return
	}
	c, err := h.DB.AddComment(r.Context(), remID, claims.UserID, req.Body)
	if err != nil {
		jsonError(w, "comment failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	logAudit(r, h.DB, "REMEDIATION_COMMENT", "remediations/comment")
	jsonOK(w, c)
}

// ════════════════════════════════════════════════════════════════════
// Phase 1 — Workflow methods (Transition, Bulk, History, KPIs)
// Adapted to real schema: remediations table (54k+ rows production data)
// Status values: open | in_progress | resolved | accepted | false_positive | fix_applied
// ════════════════════════════════════════════════════════════════════

// validRemTransitions — finite state machine khớp với status values thực tế trong DB
var validRemTransitions = map[string][]string{
	"open":           {"in_progress", "accepted", "false_positive", "fix_applied", "resolved"},
	"in_progress":    {"resolved", "open", "accepted", "fix_applied"},
	"resolved":       {"open"}, // reopen on regression
	"accepted":       {"open"}, // un-accept
	"false_positive": {"open"}, // re-investigate
	"fix_applied":    {"resolved", "open"},
}

func remContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func remActor(r *http.Request) string {
	if c, ok := auth.FromContext(r.Context()); ok && c.Email != "" {
		return c.Email
	}
	return "system"
}

// POST /api/v1/remediation/finding/{finding_id}/transition
// body: {"status":"resolved","note":"Patched in v2.4.1"}
func (h *Remediation) Transition(w http.ResponseWriter, r *http.Request) {
	defer logAudit(r, h.DB, "REMEDIATION_TRANSITION", "/remediation/transition")
	claims, _ := auth.FromContext(r.Context())
	fid := chi.URLParam(r, "finding_id")
	if !validateUUID(fid) {
		jsonError(w, "invalid finding_id", http.StatusBadRequest)
		return
	}

	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Status == "" {
		jsonError(w, "status required", http.StatusBadRequest)
		return
	}

	// Get current state (or default open)
	cur, _ := h.DB.GetRemediation(r.Context(), claims.TenantID, fid)
	currentStatus := "open"
	currentRemID := ""
	if cur != nil {
		currentStatus = string(cur.Status)
		currentRemID = cur.ID
	}

	allowed, ok := validRemTransitions[currentStatus]
	if !ok {
		// Status không trong FSM (ví dụ tự ý), cho phép → open để recover
		if req.Status != "open" {
			jsonError(w,
				fmt.Sprintf("status %q không trong FSM, chỉ cho phép -> open để recover", currentStatus),
				http.StatusBadRequest)
			return
		}
	} else if !remContains(allowed, req.Status) {
		jsonError(w,
			fmt.Sprintf("invalid transition %s -> %s (allowed: %s)",
				currentStatus, req.Status, strings.Join(allowed, ",")),
			http.StatusBadRequest)
		return
	}

	// Apply update
	fields := map[string]any{"status": req.Status}
	if req.Note != "" {
		fields["notes"] = req.Note
	}

	updated, err := h.DB.UpdateRemediationFields(r.Context(), fid, claims.TenantID, fields)
	if err != nil {
		// Fallback: row chưa tồn tại → tạo mới
		newRem := store.Remediation{
			FindingID: fid,
			TenantID:  claims.TenantID,
			Status:    store.RemediationStatus(req.Status),
			Notes:     req.Note,
			Assignee:  remActor(r),
			Priority:  "P3",
		}
		updated, err = h.DB.UpsertRemediation(r.Context(), newRem)
		if err != nil {
			jsonInternalError(w, r, "db error", err)
			return
		}
	}

	// Audit history (best-effort)
	if updated != nil {
		_ = h.DB.WriteRemediationHistory(r.Context(),
			updated.ID, remActor(r), "status_change",
			currentStatus, req.Status, req.Note)
		_ = currentRemID // keep for future reopen tracking
	}

	jsonOK(w, map[string]any{
		"ok":         true,
		"finding_id": fid,
		"from":       currentStatus,
		"to":         req.Status,
		"actor":      remActor(r),
	})
}

// POST /api/v1/remediation/bulk
// body: {"finding_ids":["uuid1","uuid2"],"action":"resolve","note":"Bulk patched"}
func (h *Remediation) Bulk(w http.ResponseWriter, r *http.Request) {
	defer logAudit(r, h.DB, "REMEDIATION_BULK", "/remediation/bulk")
	claims, _ := auth.FromContext(r.Context())

	var req struct {
		FindingIDs []string `json:"finding_ids"`
		Action     string   `json:"action"`
		Note       string   `json:"note"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.FindingIDs) == 0 {
		jsonError(w, "finding_ids required", http.StatusBadRequest)
		return
	}
	if len(req.FindingIDs) > 1000 {
		jsonError(w, "too many ids (max 1000)", http.StatusBadRequest)
		return
	}

	statusMap := map[string]string{
		"resolve": "resolved",
		"accept":  "accepted",
		"reopen":  "open",
		"mark_fp": "false_positive",
		"fix":     "fix_applied",
		"start":   "in_progress",
	}
	target, ok := statusMap[req.Action]
	if !ok {
		jsonError(w, "invalid action (resolve|accept|reopen|mark_fp|fix|start)",
			http.StatusBadRequest)
		return
	}

	actor := remActor(r)
	updated := 0
	skipped := 0

	for _, fid := range req.FindingIDs {
		if !validateUUID(fid) {
			skipped++
			continue
		}

		// Get prev for history
		prev, _ := h.DB.GetRemediation(r.Context(), claims.TenantID, fid)
		prevStatus := "open"
		if prev != nil {
			prevStatus = string(prev.Status)
		}

		fields := map[string]any{"status": target}
		if req.Note != "" {
			fields["notes"] = req.Note
		}
		rec, err := h.DB.UpdateRemediationFields(r.Context(), fid, claims.TenantID, fields)
		if err != nil {
			// Try upsert
			newRem := store.Remediation{
				FindingID: fid,
				TenantID:  claims.TenantID,
				Status:    store.RemediationStatus(target),
				Notes:     req.Note,
				Assignee:  actor,
				Priority:  "P3",
			}
			rec, err = h.DB.UpsertRemediation(r.Context(), newRem)
			if err != nil {
				skipped++
				continue
			}
		}
		updated++
		if rec != nil {
			_ = h.DB.WriteRemediationHistory(r.Context(),
				rec.ID, actor, "bulk_"+req.Action,
				prevStatus, target, req.Note)
		}
	}

	jsonOK(w, map[string]any{
		"ok":        true,
		"action":    req.Action,
		"requested": len(req.FindingIDs),
		"updated":   updated,
		"skipped":   skipped,
	})
}

// GET /api/v1/remediation/finding/{finding_id}/history
func (h *Remediation) History(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	fid := chi.URLParam(r, "finding_id")
	if !validateUUID(fid) {
		jsonError(w, "invalid finding_id", http.StatusBadRequest)
		return
	}

	rem, err := h.DB.GetRemediation(r.Context(), claims.TenantID, fid)
	if err != nil || rem == nil {
		jsonOK(w, map[string]any{"finding_id": fid, "history": []any{}})
		return
	}

	history, err := h.DB.ListRemediationHistory(r.Context(), rem.ID, 200)
	if err != nil {
		jsonInternalError(w, r, "db error", err)
		return
	}

	jsonOK(w, map[string]any{
		"finding_id": fid,
		"rem_id":     rem.ID,
		"history":    history,
		"count":      len(history),
	})
}

// GET /api/v1/remediation/kpis
// Tổng hợp count cho dashboard cards. Tenant-scoped.
func (h *Remediation) KPIs(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	stats, err := h.DB.RemediationStats(r.Context(), claims.TenantID)
	if err != nil {
		jsonInternalError(w, r, "db error", err)
		return
	}

	total := 0
	for _, n := range stats {
		total += n
	}

	resolved := stats["resolved"] + stats["fix_applied"]
	rate := 0.0
	if total > 0 {
		rate = float64(resolved) / float64(total) * 100.0
	}

	overdue, _ := h.DB.CountOverdueRemediations(r.Context(), claims.TenantID)

	jsonOK(w, map[string]any{
		"open":            stats["open"],
		"in_progress":     stats["in_progress"],
		"resolved":        stats["resolved"],
		"fix_applied":     stats["fix_applied"],
		"accepted":        stats["accepted"],
		"false_positive":  stats["false_positive"],
		"overdue":         overdue,
		"total":           total,
		"resolution_rate": fmt.Sprintf("%.1f", rate),
	})
}
