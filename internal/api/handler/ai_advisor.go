package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/vsp/platform/internal/ai"
	"github.com/vsp/platform/internal/auth"
)

// AIAdvisorHandler exposes AI Compliance Advisor endpoints.
type AIAdvisorHandler struct {
	DB           *sql.DB
	Orchestrator *ai.Orchestrator
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONHelper(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONHelper(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
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
	writeJSONHelper(w, http.StatusOK, map[string]string{"status": "recorded"})
}

func writeJSONHelper(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
