// Package handler — external Grafana embed configuration.
//
// VSP doesn't run Grafana itself; large customers already have one. This
// endpoint persists where their Grafana lives and which dashboards to
// surface inside VSP, then the static panel iframes them in.
//
// Endpoints:
//
//	GET  /api/v1/grafana/config    — read tenant config (any role)
//	POST /api/v1/grafana/config    — write tenant config (admin only)
//	GET  /api/v1/grafana/embed-url — sign the embed URL with kiosk params
//
// Note: VSP never proxies Grafana traffic. The operator must configure
// their Grafana to allow iframe embedding from the VSP origin (set
// security.allow_embedding=true and configure auth proxy / shared org).
// We deliberately do NOT pass JWTs to Grafana — that would create a
// confused-deputy. Authentication between browser ↔ Grafana stays
// independent of VSP auth.
package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Grafana struct {
	DB *store.DB
}

func NewGrafana(db *store.DB) *Grafana { return &Grafana{DB: db} }

type grafanaDashboard struct {
	UID   string `json:"uid"`
	Title string `json:"title"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
}

type grafanaConfig struct {
	BaseURL      string             `json:"base_url"`
	DefaultTheme string             `json:"default_theme"`
	Dashboards   []grafanaDashboard `json:"dashboards"`
}

// GetConfig returns the saved Grafana config for the tenant.
func (h *Grafana) GetConfig(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	cfg := h.loadConfig(r, tenantID)
	jsonOK(w, cfg)
}

// SetConfig persists the Grafana config. Admin only — embedding an
// external URL inside VSP affects what every tenant user sees and
// touches the iframe trust boundary, so the operator should make this
// decision intentionally.
func (h *Grafana) SetConfig(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden — admin role required", http.StatusForbidden)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	var cfg grafanaConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	if cfg.BaseURL != "" {
		// Reject anything that isn't an http(s) URL — would let an admin
		// set javascript: URLs that the iframe panel would then load.
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			jsonError(w, "base_url must be http or https", http.StatusBadRequest)
			return
		}
	}
	if cfg.DefaultTheme != "light" && cfg.DefaultTheme != "dark" && cfg.DefaultTheme != "" {
		jsonError(w, "default_theme must be 'light', 'dark', or empty", http.StatusBadRequest)
		return
	}
	if len(cfg.Dashboards) > 16 {
		jsonError(w, "too many dashboards (max 16)", http.StatusBadRequest)
		return
	}
	for i, d := range cfg.Dashboards {
		if !isAlnumDashUID(d.UID) {
			jsonError(w, "dashboards["+itoa(i)+"].uid must be alphanumeric/dash only",
				http.StatusBadRequest)
			return
		}
		if len(d.Title) > 200 {
			cfg.Dashboards[i].Title = d.Title[:200]
		}
	}
	raw, _ := json.Marshal(cfg)
	if _, err := h.DB.Pool().Exec(r.Context(),
		`INSERT INTO feature_config (tenant_id, feature_id, config, updated_at)
		 VALUES ($1, 'grafana', $2, NOW())
		 ON CONFLICT (tenant_id, feature_id) DO UPDATE
		 SET config = EXCLUDED.config, updated_at = NOW()`,
		tenantID, raw); err != nil {
		jsonInternalError(w, r, "db error", err)
		return
	}
	logAudit(r, h.DB, "GRAFANA_CONFIG_SET", "grafana/"+tenantID)
	jsonOK(w, cfg)
}

// EmbedURL returns the iframe URL for one of the configured dashboards
// with kiosk parameters applied. The query param `uid` must match a
// dashboard the admin has whitelisted in the config.
func (h *Grafana) EmbedURL(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	uid := strings.TrimSpace(r.URL.Query().Get("uid"))
	if uid == "" {
		jsonError(w, "uid required", http.StatusBadRequest)
		return
	}
	cfg := h.loadConfig(r, tenantID)
	if cfg.BaseURL == "" {
		jsonError(w, "grafana base_url not configured", http.StatusFailedDependency)
		return
	}
	// Lookup the dashboard — only emit URLs for whitelisted UIDs so a
	// user can't pivot through this endpoint to embed arbitrary pages.
	var match *grafanaDashboard
	for i := range cfg.Dashboards {
		if cfg.Dashboards[i].UID == uid {
			match = &cfg.Dashboards[i]
			break
		}
	}
	if match == nil {
		jsonError(w, "dashboard not in tenant config", http.StatusNotFound)
		return
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	q := url.Values{}
	q.Set("kiosk", "tv")
	if cfg.DefaultTheme != "" {
		q.Set("theme", cfg.DefaultTheme)
	}
	if match.From != "" {
		q.Set("from", match.From)
	}
	if match.To != "" {
		q.Set("to", match.To)
	}
	embed := base + "/d/" + url.PathEscape(match.UID) + "?" + q.Encode()
	jsonOK(w, map[string]any{
		"uid":       match.UID,
		"title":     match.Title,
		"embed_url": embed,
	})
}

func (h *Grafana) loadConfig(r *http.Request, tenantID string) grafanaConfig {
	var raw []byte
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT config FROM feature_config WHERE tenant_id = $1 AND feature_id = 'grafana'`,
		tenantID).Scan(&raw)
	cfg := grafanaConfig{Dashboards: []grafanaDashboard{}}
	if err == nil {
		_ = json.Unmarshal(raw, &cfg)
	}
	if cfg.Dashboards == nil {
		cfg.Dashboards = []grafanaDashboard{}
	}
	return cfg
}

// isAlnumDashUID validates Grafana's dashboard UID format. They are
// alphanumeric + dash, max 40 chars, per Grafana's storage layer.
func isAlnumDashUID(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') &&
			!(r >= '0' && r <= '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
