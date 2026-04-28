// File: internal/api/handler/remediation_autoresolve.go
//
// HTTP handler for POST /api/v1/remediation/auto-resolve

package handler

import (
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/auth"
)

// AutoResolve — POST /api/v1/remediation/auto-resolve
//
// Closes open remediations whose finding's fingerprint no longer appears in a
// newer DONE run of the SAME mode for the calling tenant. Idempotent.
//
// Wire: r.Post("/api/v1/remediation/auto-resolve", remediationH.AutoResolve)
func (h *Remediation) AutoResolve(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.TenantID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	res, err := h.DB.AutoResolveOrphans(r.Context(), claims.TenantID)
	if err != nil {
		log.Error().Err(err).Str("tenant", claims.TenantID).Msg("AutoResolveOrphans failed")
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info().
		Int("resolved", res.Resolved).
		Int("checked", res.Checked).
		Int("skipped_no_newer_run", res.Skipped).
		Str("tenant", claims.TenantID).
		Msg("auto-resolved orphan remediations (per-mode, fingerprint-based)")

	jsonOK(w, res)
}
