package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/scheduler"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Scheduler struct {
	DB     *store.DB
	Engine *scheduler.Engine
}

// GET /api/v1/schedules
func (h *Scheduler) List(w http.ResponseWriter, r *http.Request) {
	scheds := h.Engine.ListSchedules(r.Context())
	if scheds == nil { scheds = []store.StoreSchedule{} }
	jsonOK(w, map[string]any{"schedules": scheds, "total": len(scheds)})
}

// POST /api/v1/schedules
func (h *Scheduler) Create(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req struct {
		Name    string `json:"name"`
		Mode    string `json:"mode"`
		Profile string `json:"profile"`
		Src     string `json:"src"`
		URL     string `json:"url"`
		Cron    string `json:"cron"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest); return
	}
	if req.Name == "" { req.Name = req.Mode + " scheduled scan" }
	if req.Mode == "" { req.Mode = "SAST" }
	if req.Profile == "" { req.Profile = "FAST" }
	if req.Cron == "" { req.Cron = "0 2 * * *" }
	req.Enabled = true

	s, err := h.Engine.AddSchedule(r.Context(), store.StoreSchedule{
		TenantID: claims.TenantID,
		Name:     req.Name,
		Mode:     req.Mode,
		Profile:  req.Profile,
		Src:      req.Src,
		URL:      req.URL,
		CronExpr: req.Cron,
		Enabled:  req.Enabled,
	})
	if err != nil { jsonError(w, "create failed: "+err.Error(), http.StatusInternalServerError); return }
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, s)
}

// DELETE /api/v1/schedules/{id}
func (h *Scheduler) Delete(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	h.DB.DeleteSchedule(r.Context(), claims.TenantID, id) //nolint
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/v1/drift
func (h *Scheduler) DriftEvents(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	events, err := h.DB.ListStoreDriftEvents(r.Context(), claims.TenantID, 50)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }
	if events == nil { events = []store.StoreDriftEvent{} }
	jsonOK(w, map[string]any{"events": events, "total": len(events)})
}

// POST /api/v1/schedules/{id}/run-now  — manual trigger
func (h *Scheduler) RunNow(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	scheds := h.Engine.ListSchedules(r.Context())
	id := chi.URLParam(r, "id")
	for _, s := range scheds {
		if s.ID == id && s.TenantID == claims.TenantID {
			// Trigger immediately
			h.Engine.TriggerNow(r.Context(), s)
			jsonOK(w, map[string]string{"status": "triggered", "schedule": s.Name})
			return
		}
	}
	jsonError(w, "schedule not found", http.StatusNotFound)
}

// PATCH /api/v1/schedules/{id}/toggle — enable/disable
func (h *Scheduler) Toggle(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	scheds := h.Engine.ListSchedules(r.Context())
	for _, s := range scheds {
		if s.ID == id && s.TenantID == claims.TenantID {
			s.Enabled = !s.Enabled
			h.DB.UpdateScheduleEnabled(r.Context(), claims.TenantID, id, s.Enabled) //nolint
			// engine reloads on next tick
			jsonOK(w, map[string]any{"id": id, "enabled": s.Enabled})
			return
		}
	}
	jsonError(w, "schedule not found", http.StatusNotFound)
}
