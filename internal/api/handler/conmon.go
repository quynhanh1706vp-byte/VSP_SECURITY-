package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/conmon"
)

// ConMonHandler exposes ConMon REST endpoints.
type ConMonHandler struct {
	DB *sql.DB
}

// NewConMonHandler constructs a handler with the given database.
func NewConMonHandler(db *sql.DB) *ConMonHandler {
	return &ConMonHandler{DB: db}
}

// Schedules: GET list, POST create
func (h *ConMonHandler) Schedules(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		list, err := conmon.ListSchedules(r.Context(), h.DB, tenantID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"schedules": list, "count": len(list)})

	case http.MethodPost:
		var sch conmon.Schedule
		if err := json.NewDecoder(r.Body).Decode(&sch); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		sch.TenantID = tenantID
		if claims, ok := auth.FromContext(r.Context()); ok {
			sch.CreatedBy = claims.Email
		}
		id, err := conmon.CreateSchedule(r.Context(), h.DB, sch)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// Deviations: GET list (?open=1 filters unacknowledged)
func (h *ConMonHandler) Deviations(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	openOnly := r.URL.Query().Get("open") == "1"
	list, err := conmon.ListDeviations(r.Context(), h.DB, tenantID, openOnly)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deviations": list, "count": len(list)})
}

// AckDeviation: POST /api/v1/conmon/deviations/{id}/acknowledge
func (h *ConMonHandler) AckDeviation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Path: /api/v1/conmon/deviations/{id}/acknowledge
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 6 {
		http.Error(w, `{"error":"bad path"}`, http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(parts[len(parts)-2], 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
		return
	}

	var body struct {
		Notes string `json:"notes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	ackBy := "system"
	if claims, ok := auth.FromContext(r.Context()); ok {
		ackBy = claims.Email
	}

	if err := conmon.AcknowledgeDeviation(r.Context(), h.DB, id, tenantID, ackBy, body.Notes); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"deviation not found or already acknowledged"}`, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

// CadenceStatus: GET /api/v1/conmon/cadence
func (h *ConMonHandler) CadenceStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	list, err := conmon.GetCadenceStatus(r.Context(), h.DB, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cadence": list, "count": len(list)})
}

// ─── helpers ────────────────────────────────────────────────────

func tenantFromCtx(r *http.Request) (string, bool) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		return "", false
	}
	return claims.TenantID, true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
