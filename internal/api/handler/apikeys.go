package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/audit"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type APIKeys struct {
	DB *store.DB
}

// GET /api/v1/admin/api-keys
func (h *APIKeys) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	keys, err := h.DB.ListAPIKeys(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"keys": keys, "total": len(keys)})
}

// POST /api/v1/admin/api-keys
func (h *APIKeys) Create(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	var req struct {
		Label      string `json:"label"`
		Role       string `json:"role"`
		ExpiryDays int    `json:"expiry_days"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Label == "" {
		jsonError(w, "label required", http.StatusBadRequest)
		return
	}
	// Whitelist roles
	validRoles := map[string]bool{"admin": true, "analyst": true, "dev": true, "auditor": true}
	if req.Label == "" {
		jsonError(w, "label required", http.StatusBadRequest)
		return
	}
	if len(req.Label) > 100 {
		jsonError(w, "label: max 100 chars", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "analyst"
	}
	if !validRoles[req.Role] {
		jsonError(w, "invalid role: must be admin|analyst|dev|auditor", http.StatusBadRequest)
		return
	}
	// ExpiryDays: max 365
	if req.ExpiryDays == 0 {
		req.ExpiryDays = 90
	}
	if req.ExpiryDays > 365 {
		req.ExpiryDays = 365
	}

	// Generate: 32-byte random → hex → prefix(8) + full(64)
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		jsonError(w, "internal error: rng failed", http.StatusInternalServerError)
		return
	}
	fullKey := "vspk_" + hex.EncodeToString(buf) // shown once
	prefix := fullKey[:12]

	hash, _ := bcrypt.GenerateFromPassword([]byte(fullKey), bcrypt.DefaultCost)
	expiry := time.Now().AddDate(0, 0, req.ExpiryDays)

	key, err := h.DB.CreateAPIKey(r.Context(), claims.TenantID,
		req.Label, prefix, string(hash), req.Role, &expiry)
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Return full key ONCE — never stored in plain text
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{
		"id":         key.ID,
		"label":      key.Label,
		"prefix":     key.Prefix,
		"role":       key.Role,
		"expires_at": key.ExpiresAt,
		"key":        fullKey, // ← shown ONCE
		"warning":    "Copy this key now — it will not be shown again",
	})
}

// DELETE /api/v1/admin/api-keys/{id}
func (h *APIKeys) Delete(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := h.DB.DeleteAPIKey(r.Context(), claims.TenantID, id); err != nil {
		jsonError(w, "delete failed", http.StatusInternalServerError)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) //nolint:gosec // G118: intentional
		defer cancel()
		prevHash, _ := h.DB.GetLastAuditHash(ctx, claims.TenantID)
		e := audit.Entry{TenantID: claims.TenantID, UserID: claims.UserID, Action: "APIKEY_DELETED", Resource: "/admin/api-keys/" + id, IP: r.RemoteAddr, PrevHash: prevHash}
		e.StoredHash = audit.Hash(e)
		h.DB.InsertAudit(r.Context(), store.AuditWriteParams{TenantID: claims.TenantID, UserID: &claims.UserID, Action: "APIKEY_DELETED", Resource: "/admin/api-keys/" + id, IP: r.RemoteAddr, PrevHash: prevHash}) //nolint:errcheck
	}()
	w.WriteHeader(http.StatusNoContent)
}
