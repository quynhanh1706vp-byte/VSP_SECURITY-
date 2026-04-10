package handler

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
)

// GET /api/v1/notifications
// Lấy 20 audit events gần nhất, format thành notification feed
func (h *Audit) Notifications(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	entries, _, err := h.DB.ListAuditPaged(r.Context(), claims.TenantID, "", 20, 0)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	type Notif struct {
		ID        int64     `json:"id"`
		Title     string    `json:"title"`
		Body      string    `json:"body"`
		Icon      string    `json:"icon"`
		Level     string    `json:"level"` // info | warn | critical
		Read      bool      `json:"read"`
		CreatedAt time.Time `json:"created_at"`
	}

	iconMap := map[string]string{
		"login":               "🔑",
		"logout":              "🔒",
		"scan.triggered":      "▷",
		"scan.done":           "✓",
		"scan.failed":         "✗",
		"gate.fail":           "⚠",
		"gate.pass":           "✓",
		"user.created":        "👤",
		"user.deleted":        "🗑",
		"policy.created":      "📋",
		"policy.deleted":      "📋",
		"apikey.created":      "🔑",
		"apikey.deleted":      "🔑",
		"webhook.fired":       "📡",
		"remediation.updated": "🔧",
	}
	levelMap := map[string]string{
		"scan.failed":    "critical",
		"gate.fail":      "warn",
		"user.deleted":   "warn",
		"apikey.deleted": "warn",
	}

	notifs := make([]Notif, 0, len(entries))
	for _, e := range entries {
		icon := "◈"
		if v, ok := iconMap[e.Action]; ok {
			icon = v
		}
		level := "info"
		if v, ok := levelMap[e.Action]; ok {
			level = v
		}
		body := e.Resource
		if body == "" {
			body = e.Action
		}
		notifs = append(notifs, Notif{
			ID:        e.Seq,
			Title:     e.Action,
			Body:      body,
			Icon:      icon,
			Level:     level,
			Read:      false,
			CreatedAt: e.CreatedAt,
		})
	}

	jsonOK(w, map[string]any{
		"notifications": notifs,
		"unread":        len(notifs),
	})
}
