package handler

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
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
	if !decodeJSON(w, r, &req) {
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

// UpdatePlan — PUT /api/v1/admin/tenants/{id}/plan (superadmin only).
// Switches a tenant's billing plan (starter ↔ pro ↔ enterprise) without
// touching Stripe — that path lives in the webhook handler. Used for ops
// overrides, free trials, comp accounts. Audit-logged.
func (u *Users) UpdatePlan(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	// L8 2026-05-09: previously this handler only checked Role == "admin"
	// and then UPDATEd `tenants WHERE id = $url_param`. Tenant-A's admin
	// could change tenant-B's plan — proven by L8 9.5.1 which observed
	// the plan flip starter→enterprise across tenants. Real horizontal
	// privilege escalation. Fix: caller's tenant (resolved from JWT)
	// MUST equal the target id. If a future "platform admin" role
	// needs cross-tenant authority, add a separate role check above
	// rather than weakening this guard.
	callerTenantUUID := resolveTenantUUID(r.Context(), u.DB, claims.TenantID)
	if callerTenantUUID == "" {
		callerTenantUUID = claims.TenantID
	}
	if id != callerTenantUUID {
		jsonError(w, "forbidden — admin scope is your own tenant", http.StatusForbidden)
		return
	}

	var req struct {
		Plan string `json:"plan"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	plan := strings.ToLower(strings.TrimSpace(req.Plan))
	allowed := map[string]bool{"starter": true, "pro": true, "enterprise": true, "free": true}
	if !allowed[plan] {
		jsonError(w, "plan must be one of: starter, pro, enterprise, free", http.StatusBadRequest)
		return
	}

	// Capture previous plan for audit context
	var prevPlan string
	_ = u.DB.Pool().QueryRow(r.Context(),
		`SELECT plan FROM tenants WHERE id = $1`, id).Scan(&prevPlan)

	tag, err := u.DB.Pool().Exec(r.Context(),
		`UPDATE tenants SET plan = $1 WHERE id = $2`, plan, id)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "tenant not found", http.StatusNotFound)
		return
	}

	logAudit(r, u.DB, "TENANT_PLAN_UPDATE",
		"tenants/"+id+":"+prevPlan+"->"+plan)
	jsonOK(w, map[string]any{"id": id, "plan": plan, "previous": prevPlan})
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
