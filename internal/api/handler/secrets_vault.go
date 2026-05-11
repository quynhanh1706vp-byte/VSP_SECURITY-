package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
)

// ─── PRO "Secret Vault" feature endpoints ────────────────────────────────────
// Adds rotate / audit-log / config / summary on top of the basic
// list/create/delete from soar_engine.go. Routes are mounted from
// cmd/gateway/main.go and PRO-gated by middleware.RequirePro.

// ── Single-secret metadata ────────────────────────────────────────────────────

type secretMetaOut struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	LastUsedBy  string     `json:"last_used_by,omitempty"`
	UseCount    int64      `json:"use_count"`
}

// GetSecretMeta — GET /api/v1/soar/secrets/{name}
// Returns metadata only, never the value.
func (h *SOARv2) GetSecretMeta(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := chi.URLParam(r, "name")
	if !isValidSecretName(name) {
		jsonError(w, "invalid name", http.StatusBadRequest)
		return
	}
	if h.Vault == nil {
		jsonError(w, "vault not initialized", http.StatusServiceUnavailable)
		return
	}
	secrets, err := h.Vault.List(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "list: "+err.Error(), http.StatusInternalServerError)
		return
	}
	for _, s := range secrets {
		if s.Name == name {
			jsonOK(w, secretMetaOut{
				Name: s.Name, Description: s.Description, CreatedBy: s.CreatedBy,
				CreatedAt: s.CreatedAt, LastUsedAt: s.LastUsedAt, LastUsedBy: s.LastUsedBy,
				UseCount: s.UseCount,
			})
			return
		}
	}
	jsonError(w, "not found", http.StatusNotFound)
}

// ── Rotate ────────────────────────────────────────────────────────────────────

// RotateSecret — POST /api/v1/soar/secrets/{name}/rotate
// Body: {"value": "<new value>"}
// Re-encrypts the secret in place. Audit-logs as 'rotate' (writes via vault.Put
// which also writes a 'create' audit row — we leave it; "rotate" semantics are
// captured by the fact that the secret existed before).
func (h *SOARv2) RotateSecret(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.Vault == nil {
		jsonError(w, "vault not initialized", http.StatusServiceUnavailable)
		return
	}
	name := chi.URLParam(r, "name")
	if !isValidSecretName(name) {
		jsonError(w, "invalid name", http.StatusBadRequest)
		return
	}
	var req struct {
		Value       string `json:"value"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Value == "" {
		jsonError(w, "value required", http.StatusBadRequest)
		return
	}

	// Verify the secret already exists (rotate ≠ create).
	secrets, err := h.Vault.List(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "list: "+err.Error(), http.StatusInternalServerError)
		return
	}
	found := false
	prevDesc := ""
	for _, s := range secrets {
		if s.Name == name {
			found = true
			prevDesc = s.Description
			break
		}
	}
	if !found {
		jsonError(w, "secret does not exist — use POST /secrets to create", http.StatusNotFound)
		return
	}
	desc := req.Description
	if desc == "" {
		desc = prevDesc
	}
	if err := h.Vault.Put(r.Context(), claims.TenantID, name, req.Value, desc, claims.UserID); err != nil {
		jsonError(w, "rotate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Best-effort 'rotate' audit row (vault.Put already wrote a 'create' row;
	// the explicit 'rotate' marker makes the audit timeline clearer).
	_ = h.DB.WriteSecretAudit(r.Context(), claims.TenantID, name, "", "rotate", claims.UserID)

	jsonOK(w, map[string]any{"name": name, "rotated": true, "rotated_at": time.Now().UTC()})
}

// ── Audit log ─────────────────────────────────────────────────────────────────

type secretAuditRow struct {
	ID         int64     `json:"id"`
	SecretName string    `json:"secret_name"`
	RunID      *string   `json:"run_id,omitempty"`
	Action     string    `json:"action"`
	Actor      string    `json:"actor"`
	AccessedAt time.Time `json:"accessed_at"`
}

// SecretAuditLog — GET /api/v1/soar/secrets/audit?name=<name>&limit=<n>
func (h *SOARv2) SecretAuditLog(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	limit := queryInt(r, "limit", 100)
	if limit > 1000 {
		limit = 1000
	}
	if limit < 1 {
		limit = 100
	}

	var nameFilter any
	if name := q.Get("name"); name != "" {
		if !isValidSecretName(name) {
			jsonError(w, "invalid name filter", http.StatusBadRequest)
			return
		}
		nameFilter = name
	}

	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id, secret_name, run_id, action, actor, accessed_at
		   FROM playbook_secret_audit
		  WHERE tenant_id = $1
		    AND ($2::text IS NULL OR secret_name = $2)
		  ORDER BY accessed_at DESC
		  LIMIT $3`,
		claims.TenantID, nameFilter, limit)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []secretAuditRow{}
	for rows.Next() {
		var a secretAuditRow
		if err := rows.Scan(&a.ID, &a.SecretName, &a.RunID, &a.Action, &a.Actor, &a.AccessedAt); err != nil {
			continue
		}
		out = append(out, a)
	}
	jsonOK(w, map[string]any{"entries": out, "total": len(out)})
}

// ── Per-tenant vault config (PRO "view details" panel) ──────────────────────

type vaultConfig struct {
	RotationDays     int       `json:"rotation_days"`
	AuditRetentionD  int       `json:"audit_retention_days"`
	RequireApproval  bool      `json:"require_approval"`
	AllowedProviders []string  `json:"allowed_providers"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// GetVaultConfig — GET /api/v1/soar/secrets/config
// Upserts a default row on first access so the response shape is stable.
func (h *SOARv2) GetVaultConfig(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var (
		cfg       vaultConfig
		providers string
	)
	err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO secret_vault_config(tenant_id) VALUES($1)
		 ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id
		 RETURNING rotation_days, audit_retention_d, require_approval,
		           allowed_providers, updated_at`,
		claims.TenantID,
	).Scan(&cfg.RotationDays, &cfg.AuditRetentionD, &cfg.RequireApproval, &providers, &cfg.UpdatedAt)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	cfg.AllowedProviders = splitCSV(providers)
	jsonOK(w, cfg)
}

// UpdateVaultConfig — PUT /api/v1/soar/secrets/config
func (h *SOARv2) UpdateVaultConfig(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		RotationDays     int      `json:"rotation_days"`
		AuditRetentionD  int      `json:"audit_retention_days"`
		RequireApproval  bool     `json:"require_approval"`
		AllowedProviders []string `json:"allowed_providers"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RotationDays < 1 || req.RotationDays > 730 {
		jsonError(w, "rotation_days must be 1..730", http.StatusBadRequest)
		return
	}
	if req.AuditRetentionD < 7 || req.AuditRetentionD > 2555 {
		jsonError(w, "audit_retention_days must be 7..2555", http.StatusBadRequest)
		return
	}
	allowed := map[string]bool{"internal": true, "vault": true, "kms": true, "aws": true, "gcp": true, "azure": true}
	for _, p := range req.AllowedProviders {
		if !allowed[strings.ToLower(strings.TrimSpace(p))] {
			jsonError(w, "allowed_providers must be subset of internal/vault/kms/aws/gcp/azure", http.StatusBadRequest)
			return
		}
	}
	provCSV := strings.ToLower(strings.Join(req.AllowedProviders, ","))
	if provCSV == "" {
		provCSV = "internal"
	}

	_, err := h.DB.Pool().Exec(r.Context(),
		`INSERT INTO secret_vault_config(tenant_id, rotation_days, audit_retention_d,
		                                  require_approval, allowed_providers, updated_at)
		 VALUES($1,$2,$3,$4,$5,NOW())
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   rotation_days     = EXCLUDED.rotation_days,
		   audit_retention_d = EXCLUDED.audit_retention_d,
		   require_approval  = EXCLUDED.require_approval,
		   allowed_providers = EXCLUDED.allowed_providers,
		   updated_at        = NOW()`,
		claims.TenantID, req.RotationDays, req.AuditRetentionD,
		req.RequireApproval, provCSV)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

// ── Summary (counts + rotation stats for dashboard tile) ─────────────────────

type vaultSummary struct {
	Total         int        `json:"total"`
	StaleCount    int        `json:"stale_count"`   // not used in last 30d
	OverdueCount  int        `json:"overdue_count"` // older than rotation_days
	LastCreatedAt *time.Time `json:"last_created_at,omitempty"`
	RotationDays  int        `json:"rotation_days"` // current policy
}

// VaultSummary — GET /api/v1/soar/secrets/summary
func (h *SOARv2) VaultSummary(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.Vault == nil {
		jsonError(w, "vault not initialized", http.StatusServiceUnavailable)
		return
	}
	secrets, err := h.Vault.List(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "list: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Resolve current rotation policy (defaults to 90 if no config row).
	rotation := 90
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT rotation_days FROM secret_vault_config WHERE tenant_id=$1`,
		claims.TenantID).Scan(&rotation)

	now := time.Now()
	staleCutoff := now.AddDate(0, 0, -30)
	overdueCutoff := now.AddDate(0, 0, -rotation)

	out := vaultSummary{Total: len(secrets), RotationDays: rotation}
	var lastCreated *time.Time
	for i := range secrets {
		s := secrets[i]
		if s.LastUsedAt == nil || s.LastUsedAt.Before(staleCutoff) {
			out.StaleCount++
		}
		if s.CreatedAt.Before(overdueCutoff) {
			out.OverdueCount++
		}
		if lastCreated == nil || s.CreatedAt.After(*lastCreated) {
			c := s.CreatedAt
			lastCreated = &c
		}
	}
	out.LastCreatedAt = lastCreated
	jsonOK(w, out)
}
