package handler

import (
	"net/http"

	"github.com/vsp/platform/internal/auth"
)

// GET /api/v1/tenants — list tenants the current user can access
// Hiện tại: single-tenant, trả về tenant hiện tại
// Sau này: khi multi-tenant, query bảng user_tenants
func (h *Users) ListTenants(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	type TenantItem struct {
		ID      string `json:"id"`
		Slug    string `json:"slug"`
		Name    string `json:"name"`
		Plan    string `json:"plan"`
		Current bool   `json:"current"`
	}

	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id, slug, name, plan FROM tenants WHERE active = true ORDER BY name`)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var tenants []TenantItem
	for rows.Next() {
		var t TenantItem
		rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Plan) //nolint
		t.Current = t.ID == claims.TenantID
		tenants = append(tenants, t)
	}
	if tenants == nil {
		tenants = []TenantItem{}
	}
	jsonOK(w, map[string]any{"tenants": tenants, "current_tenant_id": claims.TenantID})
}
