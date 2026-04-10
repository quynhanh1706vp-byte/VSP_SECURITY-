package handler

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

var slugRe = regexp.MustCompile(`^[a-z0-9-]{2,32}$`)

// CreateTenant — POST /api/v1/admin/tenants (superadmin only)
func (u *Users) CreateTenant(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	var req struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
		Plan string `json:"plan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	req.Name = strings.TrimSpace(req.Name)
	if req.Plan == "" {
		req.Plan = "starter"
	}

	if !slugRe.MatchString(req.Slug) {
		jsonError(w, "slug must be 2-32 lowercase alphanumeric or hyphen", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name required", http.StatusBadRequest)
		return
	}

	var id string
	err := u.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO tenants(slug, name, plan) VALUES($1, $2, $3)
		 ON CONFLICT(slug) DO NOTHING
		 RETURNING id`,
		req.Slug, req.Name, req.Plan,
	).Scan(&id)
	if err != nil || id == "" {
		jsonError(w, "slug already exists or db error", http.StatusConflict)
		return
	}

	// Audit log
	prevHash, _ := u.DB.GetLastAuditHash(r.Context(), claims.TenantID)
	u.DB.InsertAudit(r.Context(), store.AuditWriteParams{TenantID: claims.TenantID, UserID: &claims.UserID, Action: "TENANT_CREATED", Resource: "/admin/tenants/" + id, IP: r.RemoteAddr, PrevHash: prevHash}) //nolint:errcheck

	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": id, "slug": req.Slug, "name": req.Name, "plan": req.Plan})
}

// ListAllTenants — GET /api/v1/admin/tenants (superadmin only)
func (u *Users) ListAllTenants(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	rows, err := u.DB.Pool().Query(r.Context(),
		`SELECT id, slug, name, plan, active, created_at FROM tenants ORDER BY created_at DESC`)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type TenantRow struct {
		ID        string    `json:"id"`
		Slug      string    `json:"slug"`
		Name      string    `json:"name"`
		Plan      string    `json:"plan"`
		Active    bool      `json:"active"`
		CreatedAt time.Time `json:"created_at"`
	}
	var tenants []TenantRow
	for rows.Next() {
		var t TenantRow
		rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Plan, &t.Active, &t.CreatedAt) //nolint
		tenants = append(tenants, t)
	}
	if tenants == nil {
		tenants = []TenantRow{}
	}
	jsonOK(w, map[string]any{"tenants": tenants, "total": len(tenants)})
}
