package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// FeatureConfig is a generic per-tenant config store used by every SIEM
// panel that doesn't need its own typed table. Each panel writes its
// settings into the JSONB column under a stable feature_id; the FE
// formModal definition (vsp_pro_realapi.js) decides the shape.
type FeatureConfig struct {
	DB *store.DB
}

func NewFeatureConfig(db *store.DB) *FeatureConfig { return &FeatureConfig{DB: db} }

// resolveTenantUUID accepts either a UUID directly or a slug (from
// dev mint_jwt_local.sh tokens) and returns the canonical UUID. Same
// helper pattern used by Threat Hunt + Findings handlers — without it
// the FK to tenants(id) blows up with "invalid input syntax for uuid".
func (h *FeatureConfig) resolveTenantUUID(r *http.Request, raw string) string {
	if raw == "" {
		return ""
	}
	if len(raw) == 36 && raw[8] == '-' && raw[13] == '-' && raw[18] == '-' && raw[23] == '-' {
		return raw
	}
	var id string
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT id::text FROM tenants WHERE slug = $1 LIMIT 1`, raw).Scan(&id)
	return id
}

// validFeatures matches the CHECK constraint in migration 026.
// Migration 028 extends the constraint to cover the settings_* prefix
// so the Settings panel's per-tab Save buttons can persist via this
// generic endpoint instead of needing one Go handler per tab section.
var validFeatures = map[string]bool{
	"ai_analyst":    true,
	"scheduler":     true,
	"correlation":   true,
	"soar":          true,
	"log_ingestion": true,
	"ueba":          true,
	"assets":        true,
	"sw_inventory":  true,
	"network_flow":  true,
	"threat_hunt":   true,
	"vuln_mgmt":     true,
	"threat_intel":  true,
	// Settings panel tabs:
	"settings_general":   true,
	"settings_scan":      true,
	"settings_alerts":    true,
	"settings_apikeys":   true,
	"settings_security":  true,
	"settings_health":    true,
	"settings_retention": true,
	// Inline REPORTS panels (from Pass 1B inline-decorator):
	"analytics": true,
	"executive": true,
	"export":    true,
	// Iframe REPORTS panels (from Pass 1A companion):
	"users":        true,
	"cicd":         true,
	"integrations": true,
	"settings":     true,
	// Sprint 3 (migration 031) — cATO toggle.
	"cato": true,
	// Sprint 4 (migration 033) — Grafana embed config.
	"grafana": true,
	// Sprint 12 (migration 045) — admin-only system toggles
	// (SSE live, session timer, session minutes). Listed in
	// adminOnlyFeatures below so the role check fires.
	"system_toggles": true,
}

// adminOnlyFeatures lists feature_ids that affect *system-level*
// behaviour (auth, audit, telemetry surfaces) and therefore require
// admin role to mutate. Lower-impact panel configs (e.g. ai_analyst
// preferences) stay role-free so analysts can self-serve.
//
// Adding a feature_id here is the security gate; UI hint alone is
// insufficient (the pre-Sprint-12.4 bug was a UI claiming "admin
// required" while the server happily accepted analyst tokens).
var adminOnlyFeatures = map[string]bool{
	"system_toggles":     true,
	"cato":               true,
	"grafana":            true,
	"settings_security":  true,
	"settings_apikeys":   true,
	"settings_retention": true,
}

// Get — GET /api/v1/features/{id}/config
// Returns the stored config (or {} if never written).
func (h *FeatureConfig) Get(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if !validFeatures[id] {
		jsonError(w, "unknown feature_id", http.StatusBadRequest)
		return
	}
	tenantID := h.resolveTenantUUID(r, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}

	var cfg []byte
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT config::text FROM feature_config
		 WHERE tenant_id=$1 AND feature_id=$2`,
		tenantID, id,
	).Scan(&cfg)
	if err != nil {
		// No row yet — return empty object, not 404. The panel form will
		// just show defaults.
		jsonOK(w, map[string]any{"feature_id": id, "config": map[string]any{}})
		return
	}
	out := struct {
		FeatureID string          `json:"feature_id"`
		Config    json.RawMessage `json:"config"`
	}{id, json.RawMessage(cfg)}
	jsonOK(w, out)
}

// Put — PUT /api/v1/features/{id}/config
// Body: { "config": {...} }  (the panel's settings as a JSON object)
// Upserts. We don't validate the shape server-side — that's the FE's job.
// We do cap size at 64KB to prevent abuse.
func (h *FeatureConfig) Put(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if !validFeatures[id] {
		jsonError(w, "unknown feature_id", http.StatusBadRequest)
		return
	}
	// Sprint 12.4: enforce admin role for system-level features.
	// Without this gate the UI's "Admin role required" hint is a lie
	// and any authenticated user can flip SSE / session timer / Vault
	// requirements globally for their tenant.
	if adminOnlyFeatures[id] && claims.Role != "admin" {
		jsonError(w, "forbidden — admin role required for "+id, http.StatusForbidden)
		return
	}
	tenantID := h.resolveTenantUUID(r, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	var req struct {
		Config json.RawMessage `json:"config"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Config) == 0 {
		req.Config = json.RawMessage(`{}`)
	}
	if len(req.Config) > 64*1024 {
		jsonError(w, "config too large (max 64KB)", http.StatusBadRequest)
		return
	}
	// Validate the body is actually a JSON object (not a number/array).
	var probe map[string]any
	if err := json.Unmarshal(req.Config, &probe); err != nil {
		jsonError(w, "config must be a JSON object", http.StatusBadRequest)
		return
	}

	_, err := h.DB.Pool().Exec(r.Context(),
		`INSERT INTO feature_config(tenant_id, feature_id, config, updated_at)
		 VALUES($1, $2, $3::jsonb, NOW())
		 ON CONFLICT (tenant_id, feature_id) DO UPDATE SET
		   config     = EXCLUDED.config,
		   updated_at = NOW()`,
		tenantID, id, string(req.Config))
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	// FedRAMP AU-2: every config change is auditable. Action namespaced so
	// consumers can filter (e.g. CONFIG_UPDATE:settings_security).
	logAudit(r, h.DB, "CONFIG_UPDATE:"+id, "feature_config/"+id)
	jsonOK(w, map[string]any{"ok": true, "feature_id": id})
}
