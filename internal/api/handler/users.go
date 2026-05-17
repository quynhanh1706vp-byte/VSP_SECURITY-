package handler

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

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
	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	// L8 2026-05-09: 7th occurrence of the slug→UUID pattern (after
	// audit/verify, audit/log, findings/summary, runs.List, runs.Index,
	// kpi sanity). Caller's tenant_id may be a slug; ListUsers queries
	// a uuid column. Without this resolve the endpoint silently returns
	// 0 users for the entire tenant, which then masquerades as "no
	// users to show" in the dashboard.
	tenantUUID := resolveTenantUUID(r.Context(), u.DB, claims.TenantID)
	if tenantUUID == "" {
		tenantUUID = claims.TenantID
	}

	users, total, err := u.DB.ListUsers(r.Context(), tenantUUID, limit, offset)
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
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Password == "" {
		jsonError(w, "email and password required", http.StatusBadRequest)
		return
	}
	// Whitelist roles — không cho phép role tùy ý
	validRoles := map[string]bool{"admin": true, "analyst": true, "dev": true, "auditor": true}
	if req.Role == "" {
		req.Role = "analyst"
	}
	if !validRoles[req.Role] {
		jsonError(w, "invalid role: must be admin|analyst|dev|auditor", http.StatusBadRequest)
		return
	}
	// Password strength check
	if len(req.Password) < 12 {
		jsonError(w, "password must be at least 12 characters", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	user, err := u.DB.CreateUser(r.Context(), claims.TenantID, req.Email, string(hash), req.Role)
	if err != nil {
		jsonError(w, "create user failed", http.StatusBadRequest)
		return
	}
	// Audit log
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		prevHash, _ := u.DB.GetLastAuditHash(ctx, claims.TenantID)
		e := audit.Entry{TenantID: claims.TenantID, UserID: claims.UserID, Action: "USER_CREATED", Resource: "/admin/users/" + user.ID, IP: r.RemoteAddr, PrevHash: prevHash}
		e.StoredHash = audit.Hash(e)
		u.DB.InsertAudit(r.Context(), store.AuditWriteParams{TenantID: claims.TenantID, UserID: &claims.UserID, Action: "USER_CREATED", Resource: "/admin/users/" + user.ID, IP: r.RemoteAddr, PrevHash: prevHash}) //nolint:errcheck
	}()
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, user)
}

// DELETE /api/v1/admin/users/{id}
func (u *Users) Delete(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if err := u.DB.DeleteUser(r.Context(), claims.TenantID, id); err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		prevHash, _ := u.DB.GetLastAuditHash(ctx, claims.TenantID)
		e := audit.Entry{TenantID: claims.TenantID, UserID: claims.UserID, Action: "USER_DELETED", Resource: "/admin/users/" + id, IP: r.RemoteAddr, PrevHash: prevHash}
		e.StoredHash = audit.Hash(e)
		u.DB.InsertAudit(r.Context(), store.AuditWriteParams{TenantID: claims.TenantID, UserID: &claims.UserID, Action: "USER_DELETED", Resource: "/admin/users/" + id, IP: r.RemoteAddr, PrevHash: prevHash}) //nolint:errcheck
	}()
	w.WriteHeader(http.StatusNoContent)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	if n, ok := validatePositiveInt(v, 100000); ok {
		return n
	}
	return def
}


// PATCH /api/v1/admin/users/{id} — update role
func (u *Users) UpdateRole(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	validRoles := map[string]bool{"admin": true, "analyst": true, "dev": true, "auditor": true}
	if !validRoles[req.Role] {
		jsonError(w, "invalid role", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		jsonError(w, "id required", http.StatusBadRequest)
		return
	}
	_, err := u.DB.Pool().Exec(r.Context(),
		"UPDATE users SET role=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3",
		req.Role, id, claims.TenantID)
	if err != nil {
		jsonError(w, "update failed", http.StatusInternalServerError)
		return
	}
	logAudit(r, u.DB, "USER_ROLE_UPDATED", "users/"+id)
	jsonOK(w, map[string]string{"id": id, "role": req.Role, "status": "updated"})
}


// POST /api/v1/admin/users/invite — generate temp password + return invite link
func (u *Users) Invite(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Email == "" {
		jsonError(w, "email required", http.StatusBadRequest)
		return
	}
	validRoles := map[string]bool{"admin": true, "analyst": true, "dev": true, "auditor": true}
	if req.Role == "" { req.Role = "analyst" }
	if !validRoles[req.Role] {
		jsonError(w, "invalid role", http.StatusBadRequest)
		return
	}
	// Generate secure temp password
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	tempPass := fmt.Sprintf("VSP-%x-%x", b[:6], b[6:])
	hash, err := bcrypt.GenerateFromPassword([]byte(tempPass), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, err = u.DB.Pool().Exec(r.Context(),
		`INSERT INTO users (tenant_id, email, pw_hash, role)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (tenant_id, email) DO NOTHING`,
		claims.TenantID, req.Email, string(hash), req.Role)
	if err != nil {
		jsonError(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	logAudit(r, u.DB, "USER_INVITED", "users/invite/"+req.Email)
	jsonOK(w, map[string]any{
		"email":     req.Email,
		"role":      req.Role,
		"temp_pass": tempPass,
		"note":      "Share temp_pass securely. User should change on first login.",
		"login_url": "/login",
	})
}

// POST /api/v1/admin/users/bulk-role — bulk role change
func (u *Users) BulkRole(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		IDs  []string `json:"ids"`
		Role string   `json:"role"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.IDs) == 0 {
		jsonError(w, "ids required", http.StatusBadRequest)
		return
	}
	if len(req.IDs) > 50 {
		jsonError(w, "max 50 users per bulk op", http.StatusBadRequest)
		return
	}
	validRoles := map[string]bool{"admin": true, "analyst": true, "dev": true, "auditor": true}
	if !validRoles[req.Role] {
		jsonError(w, "invalid role", http.StatusBadRequest)
		return
	}
	updated := 0
	for _, id := range req.IDs {
		ct, err := u.DB.Pool().Exec(r.Context(),
			"UPDATE users SET role=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3",
			req.Role, id, claims.TenantID)
		if err == nil && ct.RowsAffected() > 0 { updated++ }
	}
	logAudit(r, u.DB, "USER_BULK_ROLE", fmt.Sprintf("%d users → %s", updated, req.Role))
	jsonOK(w, map[string]any{"updated": updated, "role": req.Role})
}
