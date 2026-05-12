package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/soar"
	"github.com/vsp/platform/internal/store"
)

// ════════════════════════════════════════════════════════════════════
// SOARv2 — engine-backed handler. Coexists with legacy SOAR (siem_extended.go)
// for backwards compat: legacy /run endpoint stays, new /execute uses engine.
//
// Wired in cmd/gateway/main.go after engine init (Phase 2.1.C.2).
// ════════════════════════════════════════════════════════════════════

type SOARv2 struct {
	DB      *store.DB
	Manager *soar.Manager
	Vault   *soar.Vault
	Engine  *soar.Engine
}

// ─────────────────────────────────────────────────────────────────
// Run execution
// ─────────────────────────────────────────────────────────────────

// ExecutePlaybook runs a playbook in REAL mode (sends actual HTTP/email/etc).
// Body: {"context": {...}, "trigger": "manual"} (optional)
// Returns: {"run_id": "...", "status": "...", "step_count": N, "duration_ms": N}
func (h *SOARv2) ExecutePlaybook(w http.ResponseWriter, r *http.Request) {
	h.executeImpl(w, r, false)
}

// TestPlaybook runs in TEST mode (mocks external calls, no side effects).
func (h *SOARv2) TestPlaybook(w http.ResponseWriter, r *http.Request) {
	h.executeImpl(w, r, true)
}

func (h *SOARv2) executeImpl(w http.ResponseWriter, r *http.Request, isTest bool) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid playbook id", http.StatusBadRequest)
		return
	}

	var req struct {
		Context map[string]interface{} `json:"context"`
		Trigger string                 `json:"trigger"`
	}
	// Optional body — ignore parse errors
	bodyBytes, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(bodyBytes, &req)
	// Legacy /run compat: tolerate flat body shape like
	// {"trigger":"manual","severity":"HIGH","gate":"FAIL"} (no "context" wrapper)
	if req.Context == nil && len(bodyBytes) > 0 {
		var flat map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &flat); err == nil && len(flat) > 0 {
			if t, ok := flat["trigger"].(string); ok && req.Trigger == "" {
				req.Trigger = t
			}
			delete(flat, "trigger")
			delete(flat, "context")
			if len(flat) > 0 {
				req.Context = flat
			}
		}
	}
	if req.Trigger == "" {
		if isTest {
			req.Trigger = "test"
		} else {
			req.Trigger = "manual"
		}
	}

	run, err := h.Manager.ExecuteByID(r.Context(), claims.TenantID, id, soar.ExecuteOptions{
		IsTest:       isTest,
		TriggerEvent: req.Trigger,
		TriggeredBy:  claims.UserID,
		Context:      req.Context,
	})
	if err != nil {
		jsonError(w, "execute: "+err.Error(), http.StatusBadRequest)
		return
	}

	jsonOK(w, map[string]interface{}{
		"run_id":      run.ID,
		"status":      run.Status,
		"step_count":  len(run.StepResults),
		"duration_ms": run.DurationMS,
		"is_test":     isTest,
		"error":       run.Error,
	})
}

// GetRun returns full run detail with all step results.
// GET /api/v1/soar/runs/{id}
func (h *SOARv2) GetRun(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runID := chi.URLParam(r, "id")
	if !validateUUID(runID) {
		jsonError(w, "invalid run id", http.StatusBadRequest)
		return
	}

	run, err := h.DB.GetPlaybookRunByID(r.Context(), claims.TenantID, runID)
	if err != nil {
		if errors.Is(err, store.ErrRunNotFound) {
			jsonError(w, "run not found", http.StatusNotFound)
			return
		}
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, run)
}

// CancelRun aborts an active run.
// POST /api/v1/soar/runs/{id}/cancel
func (h *SOARv2) CancelRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	if !validateUUID(runID) {
		jsonError(w, "invalid run id", http.StatusBadRequest)
		return
	}
	if err := h.Manager.CancelRun(runID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonOK(w, map[string]interface{}{"cancelled": runID})
}

// ─────────────────────────────────────────────────────────────────
// Versions + rollback
// ─────────────────────────────────────────────────────────────────

// ListPlaybookVersions returns version history.
// GET /api/v1/soar/playbooks/{id}/versions
func (h *SOARv2) ListPlaybookVersions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	versions, err := h.DB.ListPlaybookVersions(r.Context(), id, limit)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"versions": versions,
		"count":    len(versions), // page-size-not-total: TODO 2026-05-12 audit — wire CountX helper
	})
}

// RollbackVersion sets playbook.graph to a prior version.
// POST /api/v1/soar/playbooks/{id}/version/{n}/rollback
func (h *SOARv2) RollbackVersion(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	verStr := chi.URLParam(r, "n")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	version, err := strconv.Atoi(verStr)
	if err != nil || version < 1 {
		jsonError(w, "invalid version", http.StatusBadRequest)
		return
	}

	if err := h.DB.RollbackPlaybookVersion(r.Context(), id, version, claims.UserID); err != nil {
		jsonError(w, "rollback: "+err.Error(), http.StatusBadRequest)
		return
	}
	jsonOK(w, map[string]interface{}{"rolled_back_to": version})
}

// ─────────────────────────────────────────────────────────────────
// Approvals
// ─────────────────────────────────────────────────────────────────

// ListPendingApprovals — for tenant dashboard.
// GET /api/v1/soar/approvals/pending
func (h *SOARv2) ListPendingApprovals(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	approvals, err := h.DB.ListPendingApprovals(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"approvals": approvals,
		"count":     len(approvals), // page-size-not-total: TODO 2026-05-12 audit — wire CountX helper
	})
}

// DecideApproval records an approver's decision. May resume run if quorum reached.
// POST /api/v1/soar/approvals/{id}/decide
// Body: {"decision": "approved|rejected", "note": "..."}
func (h *SOARv2) DecideApproval(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid approval id", http.StatusBadRequest)
		return
	}
	var req struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Decision != "approved" && req.Decision != "rejected" {
		jsonError(w, "decision must be approved|rejected", http.StatusBadRequest)
		return
	}

	// Use email from claims as approver identity. Falls back to user ID.
	approver := claims.Email
	if approver == "" {
		approver = claims.UserID
	}

	if err := h.DB.RecordApprovalDecision(r.Context(), id, approver, req.Decision, req.Note); err != nil {
		jsonError(w, "decide: "+err.Error(), http.StatusBadRequest)
		return
	}
	jsonOK(w, map[string]interface{}{
		"approval_id": id,
		"decision":    req.Decision,
		"by":          approver,
		"at":          time.Now().UTC().Format(time.RFC3339),
	})
}

// ─────────────────────────────────────────────────────────────────
// Secrets management
// ─────────────────────────────────────────────────────────────────

// ListSecrets — metadata only, no values.
// GET /api/v1/soar/secrets
func (h *SOARv2) ListSecrets(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	if h.Vault == nil {
		jsonError(w, "vault not initialized", http.StatusServiceUnavailable)
		return
	}
	secrets, err := h.Vault.List(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "list: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"secrets": secrets,
		"count":   len(secrets), // page-size-not-total: TODO 2026-05-12 audit — wire CountX helper
	})
}

// CreateSecret encrypts and stores a secret.
// POST /api/v1/soar/secrets
// Body: {"name": "...", "value": "...", "description": "..."}
func (h *SOARv2) CreateSecret(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	if h.Vault == nil {
		jsonError(w, "vault not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Name        string `json:"name"`
		Value       string `json:"value"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" || req.Value == "" {
		jsonError(w, "name and value required", http.StatusBadRequest)
		return
	}
	// Validate name format (alphanumeric + underscore + dash, 1-64 chars)
	if !isValidSecretName(req.Name) {
		jsonError(w, "name must be 1-64 chars [a-zA-Z0-9_-]", http.StatusBadRequest)
		return
	}

	if err := h.Vault.Put(r.Context(), claims.TenantID, req.Name, req.Value, req.Description, claims.UserID); err != nil {
		jsonError(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"name":    req.Name,
		"created": true,
	})
}

// DeleteSecret removes a secret.
// DELETE /api/v1/soar/secrets/{name}
func (h *SOARv2) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	if h.Vault == nil {
		jsonError(w, "vault not initialized", http.StatusServiceUnavailable)
		return
	}
	name := chi.URLParam(r, "name")
	if !isValidSecretName(name) {
		jsonError(w, "invalid name", http.StatusBadRequest)
		return
	}
	if err := h.Vault.Delete(r.Context(), claims.TenantID, name, claims.UserID); err != nil {
		jsonError(w, "delete: "+err.Error(), http.StatusBadRequest)
		return
	}
	jsonOK(w, map[string]interface{}{
		"name":    name,
		"deleted": true,
	})
}

// isValidSecretName — allows [a-zA-Z0-9_-], 1-64 chars.
func isValidSecretName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}
