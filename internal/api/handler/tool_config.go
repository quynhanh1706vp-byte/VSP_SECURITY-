// Package handler — Phase B Step 2: tenant tool config endpoints.
//
//	GET  /api/v1/settings/tool-config            -> list all tools with enabled status
//	PUT  /api/v1/settings/tool-config            -> bulk update {tool: enabled}
//	POST /api/v1/settings/tool-config/reset      -> reset to default (delete all rows)
package handler

import (
	"net/http"
	"sort"
	"strings"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/pipeline"
	"github.com/vsp/platform/internal/store"
)

// ToolConfig handler — depends on store.DB.
type ToolConfig struct {
	DB *store.DB
}

// allKnownTools returns the canonical list of every scanner tool the platform
// can run. Combines all mode-specific tool sets to get the full universe.
// Used by GET endpoint to render the full toggle UI even for tools the tenant
// has never explicitly configured.
func allKnownTools() []string {
	seen := make(map[string]bool)
	for _, mode := range []pipeline.Mode{
		pipeline.ModeSAST, pipeline.ModeSCA, pipeline.ModeSecrets,
		pipeline.ModeIAC, pipeline.ModeDAST, pipeline.ModeNetwork,
		pipeline.ModeFull, pipeline.ModeFullSOC,
	} {
		for _, t := range pipeline.ToolNamesForMode(mode) {
			seen[t] = true
		}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// toolCategory returns the rough category for a tool, used by FE for grouping.
// Mirrors the FE category map; keep both in sync.
func toolCategory(tool string) string {
	switch tool {
	case "bandit", "semgrep", "codeql", "gosec":
		return "SAST"
	case "trivy", "grype", "license", "osv-scanner", "cosign", "retire-js", "syft", "govulncheck":
		return "SCA"
	case "gitleaks", "secretcheck", "trufflehog":
		return "SECRETS"
	case "kics", "checkov", "hadolint":
		return "IAC"
	case "nikto", "nuclei", "sslscan":
		return "DAST"
	case "nmap", "netcap":
		return "NETWORK"
	case "apisec", "gofuzz", "racedetect":
		return "PHASE4"
	}
	return "OTHER"
}

// GET /api/v1/settings/tool-config
//
// Returns the full enabled/disabled status for every known tool, augmented
// with category and (if any) timestamp/user metadata.
func (h *ToolConfig) Get(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.TenantID == "" {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	// Load explicit overrides (rows that exist in tenant_tool_config)
	rows, err := h.DB.ListToolConfig(r.Context(), claims.TenantID)
	if err != nil {
		jsonInternalError(w, r, "db error", err)
		return
	}
	overrides := make(map[string]store.ToolConfig, len(rows))
	for _, c := range rows {
		overrides[c.ToolName] = c
	}

	// Build response: every known tool + status (default enabled if no row)
	all := allKnownTools()
	type item struct {
		Name      string `json:"name"`
		Category  string `json:"category"`
		Enabled   bool   `json:"enabled"`
		Default   bool   `json:"default"` // true = no explicit row, using default-on
		UpdatedAt string `json:"updated_at,omitempty"`
		UpdatedBy string `json:"updated_by,omitempty"`
	}
	tools := make([]item, 0, len(all))
	enabledCount, disabledCount := 0, 0

	for _, name := range all {
		it := item{Name: name, Category: toolCategory(name), Enabled: true, Default: true}
		if c, exists := overrides[name]; exists {
			it.Enabled = c.Enabled
			it.Default = false
			it.UpdatedAt = c.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")
			if c.UpdatedBy != nil {
				it.UpdatedBy = *c.UpdatedBy
			}
		}
		if it.Enabled {
			enabledCount++
		} else {
			disabledCount++
		}
		tools = append(tools, it)
	}

	jsonOK(w, map[string]any{
		"tools":          tools,
		"total":          len(tools),
		"total_enabled":  enabledCount,
		"total_disabled": disabledCount,
	})
}

// PUT /api/v1/settings/tool-config
//
// Body: {"updates": {"kics": false, "semgrep": true}}
//
// Bulk upsert. Tools not present in the body are untouched.
func (h *ToolConfig) Update(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.TenantID == "" {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	var req struct {
		Updates map[string]bool `json:"updates"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if len(req.Updates) == 0 {
		jsonError(w, "updates: empty", http.StatusBadRequest)
		return
	}

	// Whitelist tool names against allKnownTools() to prevent typos / SQL pollution
	known := make(map[string]bool, 30)
	for _, t := range allKnownTools() {
		known[t] = true
	}
	clean := make(map[string]bool, len(req.Updates))
	for tool, enabled := range req.Updates {
		if !known[tool] {
			jsonError(w, "unknown tool: "+tool, http.StatusBadRequest)
			return
		}
		clean[tool] = enabled
	}

	// Both columns in tool_config are UUID. Dev JWTs carry slug/email, so
	// resolve before insert (same fix the audit helper applies).
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	userID := resolveUserUUID(r.Context(), h.DB, claims.UserID)
	if err := h.DB.BulkSetToolEnabled(r.Context(), tenantID, userID, clean); err != nil {
		jsonInternalError(w, r, "db error", err)
		return
	}

	// Capture which tools changed so the audit entry is searchable later
	// without having to diff before/after blobs.
	changed := make([]string, 0, len(clean))
	for t := range clean {
		changed = append(changed, t)
	}
	sort.Strings(changed)
	resource := "tool_config:" + strings.Join(changed, ",")
	if len(resource) > 240 {
		resource = resource[:237] + "..."
	}
	logAudit(r, h.DB, "TOOL_CONFIG_UPDATE", resource)

	jsonOK(w, map[string]any{
		"ok":      true,
		"updated": len(clean),
	})
}

// POST /api/v1/settings/tool-config/reset
//
// Clears all explicit overrides — every tool reverts to default-on.
func (h *ToolConfig) Reset(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.TenantID == "" {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	if err := h.DB.ResetToolConfig(r.Context(), tenantID); err != nil {
		jsonInternalError(w, r, "db error", err)
		return
	}
	logAudit(r, h.DB, "TOOL_CONFIG_RESET", "tool_config:all")
	jsonOK(w, map[string]any{"ok": true, "message": "all tools reset to default-on"})
}
