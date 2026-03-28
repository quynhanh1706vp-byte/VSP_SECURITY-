package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Remediation struct{ DB *store.DB }

// GET /api/v1/remediation — list all with optional ?status=open
func (h *Remediation) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	status := r.URL.Query().Get("status")
	list, err := h.DB.ListRemediations(r.Context(), claims.TenantID, status)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }
	if list == nil { list = []store.Remediation{} }
	jsonOK(w, map[string]any{"remediations": list, "total": len(list)})
}

// GET /api/v1/remediation/stats
func (h *Remediation) Stats(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	stats, err := h.DB.RemediationStats(r.Context(), claims.TenantID)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }
	jsonOK(w, stats)
}

// GET /api/v1/remediation/finding/{finding_id}
func (h *Remediation) Get(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	fid := chi.URLParam(r, "finding_id")
	rem, err := h.DB.GetRemediation(r.Context(), claims.TenantID, fid)
	if err != nil {
		jsonOK(w, map[string]any{"status": "open", "finding_id": fid})
		return
	}
	// Also load comments
	comments, _ := h.DB.ListComments(r.Context(), rem.ID)
	if comments == nil { comments = []store.RemediationComment{} }
	jsonOK(w, map[string]any{"remediation": rem, "comments": comments})
}

// POST /api/v1/remediation/finding/{finding_id}
func (h *Remediation) Upsert(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	fid := chi.URLParam(r, "finding_id")
	var req struct {
		Status    string `json:"status"`
		Assignee  string `json:"assignee"`
		Priority  string `json:"priority"`
		Notes     string `json:"notes"`
		TicketURL string `json:"ticket_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest); return
	}
	if req.Status == "" { req.Status = "open" }
	if req.Priority == "" { req.Priority = "P3" }
	rem, err := h.DB.UpsertRemediation(r.Context(), store.Remediation{
		FindingID: fid,
		TenantID:  claims.TenantID,
		Status:    store.RemediationStatus(req.Status),
		Assignee:  req.Assignee,
		Priority:  req.Priority,
		Notes:     req.Notes,
		TicketURL: req.TicketURL,
	})
	if err != nil { jsonError(w, "upsert failed: "+err.Error(), http.StatusInternalServerError); return }
	jsonOK(w, rem)
}

// POST /api/v1/remediation/{rem_id}/comments
func (h *Remediation) AddComment(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	remID := chi.URLParam(r, "rem_id")
	var req struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Body == "" {
		jsonError(w, "body required", http.StatusBadRequest); return
	}
	c, err := h.DB.AddComment(r.Context(), remID, claims.UserID, req.Body)
	if err != nil { jsonError(w, "comment failed", http.StatusInternalServerError); return }
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, c)
}
