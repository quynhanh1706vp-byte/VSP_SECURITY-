package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

type WorkerHealth struct {
	lastIteration  atomic.Int64
	itemsProcessed atomic.Uint64
	errorsTotal    atomic.Uint64
	startedAt      time.Time
	staleThreshold time.Duration
}

func NewWorkerHealth(stale time.Duration) *WorkerHealth {
	wh := &WorkerHealth{
		startedAt:      time.Now(),
		staleThreshold: stale,
	}
	wh.lastIteration.Store(time.Now().UnixNano())
	return wh
}

func (w *WorkerHealth) Tick(processed int, errs int) {
	w.lastIteration.Store(time.Now().UnixNano())
	if processed > 0 {
		w.itemsProcessed.Add(uint64(processed))
	}
	if errs > 0 {
		w.errorsTotal.Add(uint64(errs))
	}
}

func (w *WorkerHealth) Snapshot() map[string]any {
	last := time.Unix(0, w.lastIteration.Load())
	age := time.Since(last)
	status := "healthy"
	if age > w.staleThreshold {
		status = "unhealthy"
	} else if age > w.staleThreshold/2 {
		status = "degraded"
	}
	return map[string]any{
		"status":          status,
		"last_iteration":  last.Format(time.RFC3339),
		"age_seconds":     int(age.Seconds()),
		"items_processed": w.itemsProcessed.Load(),
		"errors_total":    w.errorsTotal.Load(),
		"started_at":      w.startedAt.Format(time.RFC3339),
		"uptime_seconds":  int(time.Since(w.startedAt).Seconds()),
		"stale_threshold": w.staleThreshold.String(),
	}
}

type HealthHandler struct {
	AgenticHealth     *WorkerHealth
	RemediationHealth *WorkerHealth
}

func (h *HealthHandler) Agentic(w http.ResponseWriter, r *http.Request) {
	writeHealth(w, h.AgenticHealth)
}

func (h *HealthHandler) Remediation(w http.ResponseWriter, r *http.Request) {
	writeHealth(w, h.RemediationHealth)
}

func writeHealth(w http.ResponseWriter, wh *WorkerHealth) {
	w.Header().Set("Content-Type", "application/json")
	if wh == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "unknown",
			"error":  "health tracker not initialized",
		})
		return
	}
	snap := wh.Snapshot()
	if snap["status"] == "unhealthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(snap)
}

type DBPinger interface {
	PingContext(ctx context.Context) error
}

func (h *HealthHandler) DeepCheck(db DBPinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		dbOK := db.PingContext(ctx) == nil
		agentic := h.AgenticHealth.Snapshot()
		remediation := h.RemediationHealth.Snapshot()
		overall := "healthy"
		if !dbOK || agentic["status"] == "unhealthy" || remediation["status"] == "unhealthy" {
			overall = "unhealthy"
		}
		w.Header().Set("Content-Type", "application/json")
		if overall == "unhealthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      overall,
			"db":          dbOK,
			"agentic":     agentic,
			"remediation": remediation,
		})
	}
}
