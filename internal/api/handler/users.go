package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/audit"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type Users struct {
	DB *store.DB
}

// GET /api/v1/admin/users
func (u *Users) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit  := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	users, total, err := u.DB.ListUsers(r.Context(), claims.TenantID, limit, offset)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"users":  users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// POST /api/v1/admin/users
func (u *Users) Create(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Password == "" {
		jsonError(w, "email and password required", http.StatusBadRequest)
		return
	}
	// Whitelist roles — không cho phép role tùy ý
	validRoles := map[string]bool{"admin": true, "analyst": true, "dev": true, "auditor": true}
	if req.Role == "" { req.Role = "analyst" }
	if !validRoles[req.Role] {
		jsonError(w, "invalid role: must be admin|analyst|dev|auditor", http.StatusBadRequest)
		return
	}
	// Password strength check
	if len(req.Password) < 8 {
		jsonError(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	user, err := u.DB.CreateUser(r.Context(), claims.TenantID, req.Email, string(hash), req.Role)
	if err != nil {
		jsonError(w, "create user failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Audit log
	go func() {
		prevHash, _ := u.DB.GetLastAuditHash(r.Context(), claims.TenantID)
		e := audit.Entry{TenantID: claims.TenantID, UserID: claims.UserID, Action: "USER_CREATED", Resource: "/admin/users/" + user.ID, IP: r.RemoteAddr, PrevHash: prevHash}
		e.StoredHash = audit.Hash(e)
		u.DB.InsertAudit(r.Context(), store.AuditWriteParams{TenantID: claims.TenantID, UserID: &claims.UserID, Action: "USER_CREATED", Resource: "/admin/users/"+ user.ID, IP: r.RemoteAddr, PrevHash: prevHash}) //nolint:errcheck
	}()
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, user)
}

// DELETE /api/v1/admin/users/{id}
func (u *Users) Delete(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	if err := u.DB.DeleteUser(r.Context(), claims.TenantID, id); err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	go func() {
		prevHash, _ := u.DB.GetLastAuditHash(r.Context(), claims.TenantID)
		e := audit.Entry{TenantID: claims.TenantID, UserID: claims.UserID, Action: "USER_DELETED", Resource: "/admin/users/" + id, IP: r.RemoteAddr, PrevHash: prevHash}
		e.StoredHash = audit.Hash(e)
		u.DB.InsertAudit(r.Context(), store.AuditWriteParams{TenantID: claims.TenantID, UserID: &claims.UserID, Action: "USER_DELETED", Resource: "/admin/users/"+ id, IP: r.RemoteAddr, PrevHash: prevHash}) //nolint:errcheck
	}()
	w.WriteHeader(http.StatusNoContent)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" { return def }
	if n, ok := validatePositiveInt(v, 100000); ok { return n }
	return def
}
