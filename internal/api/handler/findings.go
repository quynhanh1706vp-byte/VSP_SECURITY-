package handler

import (
	"net/http"

	"strings"

	"github.com/google/uuid"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Findings struct {
	DB *store.DB
}

// GET /api/v1/vsp/findings
// --- BEGIN PATCH: run_id/rid resolver -----------------------------------------
// resolveRunID accepts UUID, rid string, or anything in between, and returns
// the canonical UUID. Also handles slug-form tenantID (dev mint tokens) so
// the query doesn't blow up with "invalid input syntax for type uuid".
func (h *Findings) resolveRunID(r *http.Request, tenantID string) string {
	q := r.URL.Query()
	val := strings.TrimSpace(q.Get("run_id"))
	if val == "" {
		val = strings.TrimSpace(q.Get("rid"))
	}
	if val == "" {
		return ""
	}
	if _, err := uuid.Parse(val); err == nil {
		return val
	}
	// Translate slug → UUID first if needed.
	tenantUUID := tenantID
	if _, err := uuid.Parse(tenantID); err != nil {
		_ = h.DB.Pool().QueryRow(r.Context(),
			`SELECT id::text FROM tenants WHERE slug=$1 LIMIT 1`, tenantID).Scan(&tenantUUID)
	}
	if tenantUUID == "" {
		return ""
	}
	var id string
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT id::text FROM runs WHERE rid=$1 AND tenant_id=$2 LIMIT 1`,
		val, tenantUUID).Scan(&id)
	return id
}

// --- END PATCH ---------------------------------------------------------------

func (h *Findings) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	q := r.URL.Query()

	// Cap limit tối đa 2000, search tối đa 200 chars
	limit := queryInt(r, "limit", 50)
	if limit > 2000 {
		limit = 2000
	}
	if limit < 1 {
		limit = 1
	}

	search := sanitizeString(q.Get("q"), 200)

	// FIX 2026-05-07: resolve both run_id (rid → UUID) AND the tenant_id
	// (slug → UUID) before hitting the store. ListFindings does
	// `WHERE f.tenant_id = $1` against a UUID column, so dev-mint tokens
	// carrying slug "default" produce a SQL type error and 0 rows.
	tenantUUID := claims.TenantID
	if _, err := uuid.Parse(claims.TenantID); err != nil {
		_ = h.DB.Pool().QueryRow(r.Context(),
			`SELECT id::text FROM tenants WHERE slug=$1 LIMIT 1`, claims.TenantID).Scan(&tenantUUID)
	}
	resolvedRunID := h.resolveRunID(r, tenantUUID)
	findings, total, err := h.DB.ListFindings(r.Context(), tenantUUID, store.FindingFilter{
		RunID:    resolvedRunID,
		Severity: q.Get("severity"),
		Tool:     q.Get("tool"),
		Search:   search,
		Limit:    limit,
		Offset:   queryInt(r, "offset", 0),
	})
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if findings == nil {
		findings = []store.Finding{}
	}
	jsonOK(w, map[string]any{
		"findings": findings,
		"total":    total,
		"limit":    limit,
		"offset":   queryInt(r, "offset", 0),
	})
}

// GET /api/v1/vsp/findings/summary
// Default: latest completed run only. ?scope=all for all-time totals.
func (h *Findings) Summary(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	// L4-B 2026-05-08: same slug→UUID resolve as List. Without this the
	// dev-mint token (tenant_id="default") goes straight into a UUID
	// column and silently returns 0 — which is what the L4 multi-tenant
	// matrix caught.
	tenantUUID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantUUID == "" {
		tenantUUID = claims.TenantID
	}

	runID := h.resolveRunID(r, tenantUUID)

	// Auto-select latest DONE run unless scope=all
	if runID == "" && r.URL.Query().Get("scope") != "all" {
		runs, err := h.DB.ListRuns(r.Context(), tenantUUID, 5, 0)
		if err == nil {
			for _, run := range runs {
				if run.Status == "DONE" {
					runID = run.ID
					break
				}
			}
		}
	}

	s, err := h.DB.FindingsSummary(r.Context(), tenantUUID, runID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, s)
}
