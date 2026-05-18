package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/vsp/platform/internal/ai"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// AIAdvisorHandler exposes AI Compliance Advisor endpoints.
//
// L8 2026-05-09: AuditDB (a *store.DB ref) is OPTIONAL — when non-nil
// the handler emits audit_log rows via logAudit on Feedback. The
// orchestrator/cache layer uses *sql.DB; audit writes through the
// main store.DB to keep the chain integrated with everything else.
type AIAdvisorHandler struct {
	DB           *sql.DB
	Orchestrator *ai.Orchestrator
	AuditDB      *store.DB
}

// SetAuditDB wires the main store.DB so write paths can emit audit
// rows. Idempotent.
func (h *AIAdvisorHandler) SetAuditDB(db *store.DB) {
	h.AuditDB = db
}

func NewAIAdvisorHandler(db *sql.DB, apiKey string, airGap bool) *AIAdvisorHandler {
	return &AIAdvisorHandler{
		DB:           db,
		Orchestrator: ai.NewOrchestrator(db, apiKey, airGap),
	}
}

// Advise: POST /api/v1/ai/advise
func (h *AIAdvisorHandler) Advise(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req ai.AdviseRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if claims, ok := auth.FromContext(r.Context()); ok {
		req.TenantID = claims.TenantID
	}

	resp, err := h.Orchestrator.Advise(r.Context(), req)
	if err != nil {
		writeJSONHelper(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSONHelper(w, http.StatusOK, resp)
}

// CacheStats: GET /api/v1/ai/cache/stats
func (h *AIAdvisorHandler) CacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	stats, err := ai.GetCacheStats(r.Context(), h.DB)
	if err != nil {
		writeJSONHelper(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	resp := map[string]any{
		"stats": stats,
		"mode":  h.Orchestrator.Mode(),
	}
	writeJSONHelper(w, http.StatusOK, resp)
}

// Mode: GET /api/v1/ai/mode — returns 'claude' or 'local'
func (h *AIAdvisorHandler) Mode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	writeJSONHelper(w, http.StatusOK, map[string]string{
		"mode": h.Orchestrator.Mode(),
	})
}

// Feedback: POST /api/v1/ai/feedback/{cache_id}
func (h *AIAdvisorHandler) Feedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, `{"error":"bad path"}`, http.StatusBadRequest)
		return
	}
	cacheID, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid cache_id"}`, http.StatusBadRequest)
		return
	}

	var body struct {
		Rating string `json:"rating"`
		Notes  string `json:"notes"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	tenantID, userEmail := "", ""
	if claims, ok := auth.FromContext(r.Context()); ok {
		tenantID = claims.TenantID
		userEmail = claims.Email
	}

	if err := ai.SubmitFeedback(r.Context(), h.DB, cacheID, tenantID, userEmail, body.Rating, body.Notes); err != nil {
		writeJSONHelper(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if h.AuditDB != nil {
		logAudit(r, h.AuditDB, "AI_FEEDBACK_SUBMITTED",
			"ai_advisor_feedback/"+strconv.FormatInt(cacheID, 10)+":"+body.Rating)
	}
	writeJSONHelper(w, http.StatusOK, map[string]string{"status": "recorded"})
}

func writeJSONHelper(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
