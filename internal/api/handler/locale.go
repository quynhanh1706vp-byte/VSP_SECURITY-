// Package handler — locale preference endpoint.
//
// GET  /api/v1/locale — returns supported locales + the user's saved one
// POST /api/v1/locale — persists the chosen locale on users.locale
//
// The i18n middleware always resolves a locale per request (from query /
// header / Accept-Language); this endpoint just lets the SPA make the
// preference sticky across browsers.
package handler

import (
	"net/http"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/i18n"
	"github.com/vsp/platform/internal/store"
)

type Locale struct {
	DB *store.DB
}

func NewLocale(db *store.DB) *Locale { return &Locale{DB: db} }

func (h *Locale) Get(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userID := resolveUserUUID(r.Context(), h.DB, claims.UserID)
	saved := ""
	if userID != "" {
		_ = h.DB.Pool().QueryRow(r.Context(),
			`SELECT COALESCE(locale,'') FROM users WHERE id = $1`, userID).Scan(&saved)
	}
	jsonOK(w, map[string]any{
		"current":   i18n.Locale(r.Context()),
		"saved":     saved,
		"supported": i18n.Supported,
	})
}

func (h *Locale) Set(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Locale string `json:"locale"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if !i18nIsSupported(body.Locale) && body.Locale != "" {
		jsonError(w, "unsupported locale", http.StatusBadRequest)
		return
	}
	userID := resolveUserUUID(r.Context(), h.DB, claims.UserID)
	if userID == "" {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	if _, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE users SET locale = $1 WHERE id = $2`, body.Locale, userID); err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"saved": body.Locale})
}

func i18nIsSupported(loc string) bool {
	for _, s := range i18n.Supported {
		if s == loc {
			return true
		}
	}
	return false
}
