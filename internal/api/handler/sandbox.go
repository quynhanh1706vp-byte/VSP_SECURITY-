package handler

import (
	"net/http"
	"sync"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/siem"
	"github.com/vsp/platform/internal/store"
)

type Sandbox struct {
	DB     *store.DB
	mu     sync.RWMutex
	events []sandboxEvent
}

type sandboxEvent struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	EventType string    `json:"event_type"`
	Payload   any       `json:"payload"`
	FiredAt   time.Time `json:"fired_at"`
}

// GET /api/v1/vsp/sandbox
func (h *Sandbox) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	h.mu.RLock()
	defer h.mu.RUnlock()
	var my []sandboxEvent
	for _, e := range h.events {
		if e.TenantID == claims.TenantID {
			my = append(my, e)
		}
	}
	if my == nil {
		my = []sandboxEvent{}
	}
	jsonOK(w, map[string]any{"events": my, "total": len(my)})
}

// POST /api/v1/vsp/sandbox/test-fire
func (h *Sandbox) TestFire(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req struct {
		EventType string `json:"event_type"`
		Gate      string `json:"gate"`
		Severity  string `json:"severity"`
	}
	if !decodeJSON(w, r, &req) {
		req.EventType = "test"
		req.Gate = "WARN"
		req.Severity = "HIGH"
	}
	event := siem.Event{
		RID:       "RID_SANDBOX_" + time.Now().Format("20060102_150405"),
		TenantID:  claims.TenantID,
		Gate:      req.Gate,
		Posture:   "B",
		Score:     75,
		Findings:  3,
		High:      3,
		Timestamp: time.Now(),
		Src:       "sandbox",
	}
	go siem.Deliver(r.Context(), h.DB, event)

	h.mu.Lock()
	h.events = append(h.events, sandboxEvent{
		ID:        event.RID,
		TenantID:  claims.TenantID,
		EventType: req.EventType,
		Payload:   event,
		FiredAt:   time.Now(),
	})
	// Cap total events to prevent memory leak
	if len(h.events) > 1000 {
		h.events = h.events[len(h.events)-500:] // keep last 500
	}
	h.mu.Unlock()

	jsonOK(w, map[string]any{
		"status": "fired",
		"rid":    event.RID,
		"event":  event,
	})
}

// DELETE /api/v1/vsp/sandbox/clear
func (h *Sandbox) Clear(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	h.mu.Lock()
	keep := h.events[:0]
	for _, e := range h.events {
		if e.TenantID != claims.TenantID {
			keep = append(keep, e)
		}
	}
	h.events = keep
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
