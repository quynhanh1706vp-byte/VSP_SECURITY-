package handler

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// ════════════════════════════════════════════════════════════════════
// Agents — endpoint agent telemetry handlers.
//
// Auth model:
//   - Enroll/list/revoke endpoints — JWT (admin user creates and manages
//     agents from the UI)
//   - Heartbeat/inventory endpoints — X-Agent-Key header (agent supplies
//     its own API key on every call). Validated via store.GetAgentByAPIKeyHash.
//
// Wired in cmd/gateway/main.go.
// ════════════════════════════════════════════════════════════════════

type Agents struct{ DB *store.DB }

// ── JWT-protected (UI) endpoints ────────────────────────────────────

// Enroll — POST /api/v1/agents/enroll
//
//	body: {hostname, os_family, os_version, arch, version}
//	returns: {id, hostname, api_key (SHOW ONCE), api_key_hint}
func (h *Agents) Enroll(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.TenantID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Hostname  string `json:"hostname"`
		OSFamily  string `json:"os_family"`
		OSVersion string `json:"os_version"`
		Arch      string `json:"arch"`
		Version   string `json:"version"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Hostname == "" {
		jsonError(w, "hostname required", http.StatusBadRequest)
		return
	}
	if len(req.Hostname) > 255 {
		jsonError(w, "hostname too long (max 255)", http.StatusBadRequest)
		return
	}

	res, err := h.DB.EnrollAgent(r.Context(), claims.TenantID, req.Hostname, req.OSFamily, req.OSVersion, req.Arch, req.Version)
	if err != nil {
		jsonError(w, "enroll: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// L8 fix: agent enrollment is identity creation — must be audited.
	logAudit(r, h.DB, "AGENT_ENROLLED", "agents/"+res.Agent.ID+":"+req.Hostname)

	// Return raw key ONCE; subsequent List/Get calls only return hint.
	jsonOK(w, map[string]interface{}{
		"id":           res.Agent.ID,
		"hostname":     res.Agent.Hostname,
		"api_key":      res.RawAPIKey, // SHOW ONCE — never returned again
		"api_key_hint": res.Agent.APIKeyHint,
		"enrolled_at":  res.Agent.EnrolledAt,
		"status":       res.Agent.Status,
	})
}

// List — GET /api/v1/agents
func (h *Agents) List(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.TenantID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	agents, err := h.DB.ListAgents(r.Context(), claims.TenantID, limit)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"agents": agents, "count": len(agents)}) // page-size-not-total: TODO 2026-05-12 audit — wire CountX helper
}

// Get — GET /api/v1/agents/{id}
func (h *Agents) Get(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.TenantID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid agent id", http.StatusBadRequest)
		return
	}
	a, err := h.DB.GetAgentByID(r.Context(), claims.TenantID, id)
	if err != nil {
		if errors.Is(err, store.ErrAgentNotFound) {
			jsonError(w, "agent not found", http.StatusNotFound)
			return
		}
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	// Include latest packages (cap 200 for response size sanity)
	pkgs, err := h.DB.ListAgentPackages(r.Context(), claims.TenantID, id, 200)
	if err != nil {
		// Non-fatal — return agent without packages
		pkgs = nil
	}
	jsonOK(w, map[string]interface{}{"agent": a, "packages": pkgs, "package_count": len(pkgs)})
}

// Revoke — DELETE /api/v1/agents/{id}
func (h *Agents) Revoke(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.TenantID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid agent id", http.StatusBadRequest)
		return
	}
	if err := h.DB.RevokeAgent(r.Context(), claims.TenantID, id); err != nil {
		if errors.Is(err, store.ErrAgentNotFound) {
			jsonError(w, "agent not found or already revoked", http.StatusNotFound)
			return
		}
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	// L8 fix: agent revocation is identity destruction — must be audited.
	logAudit(r, h.DB, "AGENT_REVOKED", "agents/"+id)
	jsonOK(w, map[string]interface{}{"id": id, "revoked": true})
}

// ── Agent X-Agent-Key authenticated endpoints ───────────────────────

// authenticateAgent — verify X-Agent-Key header → return Agent or write error.
// Returns nil on auth failure (response already written).
func (h *Agents) authenticateAgent(w http.ResponseWriter, r *http.Request) *store.Agent {
	rawKey := r.Header.Get("X-Agent-Key")
	if rawKey == "" {
		jsonError(w, "X-Agent-Key header required", http.StatusUnauthorized)
		return nil
	}
	if len(rawKey) < 16 || len(rawKey) > 200 {
		jsonError(w, "invalid agent key format", http.StatusUnauthorized)
		return nil
	}
	hash := store.HashAPIKey(rawKey)
	a, err := h.DB.GetAgentByAPIKeyHash(r.Context(), hash)
	if err != nil {
		jsonError(w, "invalid agent key", http.StatusUnauthorized)
		return nil
	}
	return a
}

// extractClientIP — best-effort source IP (X-Forwarded-For first, else RemoteAddr).
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First entry in chain
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Heartbeat — POST /api/v1/agents/heartbeat
//
//	body (optional): {version}
//	auth: X-Agent-Key
func (h *Agents) Heartbeat(w http.ResponseWriter, r *http.Request) {
	a := h.authenticateAgent(w, r)
	if a == nil {
		return
	}
	var req struct {
		Version string `json:"version"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	ip := extractClientIP(r)
	if err := h.DB.TouchAgent(r.Context(), a.ID, ip, req.Version); err != nil {
		jsonError(w, "touch: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "agent_id": a.ID, "next_heartbeat_seconds": 60})
}

// Inventory — POST /api/v1/agents/inventory
//
//	body: {packages: [{name, version, package_mgr, architecture, install_date}]}
//	auth: X-Agent-Key
func (h *Agents) Inventory(w http.ResponseWriter, r *http.Request) {
	a := h.authenticateAgent(w, r)
	if a == nil {
		return
	}
	var req struct {
		Packages []store.SoftwarePackage `json:"packages"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Packages) == 0 {
		jsonError(w, "packages array required (non-empty)", http.StatusBadRequest)
		return
	}
	if len(req.Packages) > 10000 {
		jsonError(w, "too many packages in single batch (max 10000)", http.StatusRequestEntityTooLarge)
		return
	}

	ip := extractClientIP(r)
	ua := r.Header.Get("User-Agent")
	count, err := h.DB.IngestInventory(r.Context(), a.TenantID, a.ID, ip, ua, req.Packages)
	if err != nil {
		jsonError(w, "ingest: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Touch agent on inventory submission too (counts as activity)
	_ = h.DB.TouchAgent(r.Context(), a.ID, ip, "")

	// L8 fix: agent inventory submissions are SBOM/SCA-relevant data
	// changes — auditing them lets a reviewer correlate a finding
	// burst with a specific agent ingest.
	logAudit(r, h.DB, "AGENT_INVENTORY", "agents/"+a.ID+":pkgs="+itoa(count))

	jsonOK(w, map[string]interface{}{
		"ok":            true,
		"agent_id":      a.ID,
		"package_count": count,
	})
}
