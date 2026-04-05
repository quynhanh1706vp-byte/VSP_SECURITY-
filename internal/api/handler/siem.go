package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/siem"
	"github.com/vsp/platform/internal/store"
)

type SIEM struct {
	DB *store.DB
}

// GET /api/v1/siem/webhooks
func (h *SIEM) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	hooks, err := h.DB.ListSIEMWebhooks(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if hooks == nil {
		hooks = []store.SIEMWebhook{}
	}
	jsonOK(w, map[string]any{"webhooks": hooks, "total": len(hooks)})
}

// POST /api/v1/siem/webhooks
func (h *SIEM) Create(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req struct {
		Label  string `json:"label"`
		Type   string `json:"type"`
		URL    string `json:"url"`
		Secret string `json:"secret"`
		MinSev string `json:"min_sev"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Label == "" || req.URL == "" {
		jsonError(w, "label and url required", http.StatusBadRequest)
		return
	}
	// Validate URL trước khi lưu — chặn SSRF
	if err := siem.ValidateWebhookURL(req.URL); err != nil {
		jsonError(w, "invalid webhook URL: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Whitelist webhook type
	validTypes := map[string]bool{
		"generic": true, "slack": true, "splunk_hec": true,
		"sentinel": true, "datadog": true, "cef": true,
	}
	if req.Type == "" { req.Type = "generic" }
	if !validTypes[req.Type] {
		jsonError(w, "invalid type", http.StatusBadRequest)
		return
	}
	if req.MinSev == "" { req.MinSev = "HIGH" }

	hook, err := h.DB.CreateSIEMWebhook(r.Context(), store.SIEMWebhook{
		TenantID:   claims.TenantID,
		Label:      req.Label,
		Type:       req.Type,
		URL:        req.URL,
		SecretHash: req.Secret,
		MinSev:     req.MinSev,
	})
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, hook)
}

// DELETE /api/v1/siem/webhooks/{id}
func (h *SIEM) Delete(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	h.DB.DeleteSIEMWebhook(r.Context(), claims.TenantID, id) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/v1/siem/webhooks/{id}/test
func (h *SIEM) Test(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")

	hooks, _ := h.DB.ListSIEMWebhooks(r.Context(), claims.TenantID)
	var target *store.SIEMWebhook
	for i := range hooks {
		if hooks[i].ID == id {
			target = &hooks[i]
			break
		}
	}
	if target == nil {
		jsonError(w, "webhook not found", http.StatusNotFound)
		return
	}

	testEvent := siem.Event{
		RID:       "RID_TEST_EVENT",
		TenantID:  claims.TenantID,
		Gate:      "WARN",
		Posture:   "B",
		Score:     75,
		Findings:  3,
		High:      3,
		Timestamp: time.Now(),
		Src:       "test",
	}
	go siem.Deliver(r.Context(), h.DB, testEvent)
	jsonOK(w, map[string]string{"status": "test event fired", "webhook": target.Label})
}
