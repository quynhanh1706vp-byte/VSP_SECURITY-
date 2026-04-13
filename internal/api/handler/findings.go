package handler

import (
	"net/http"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Findings struct {
	DB *store.DB
}

// GET /api/v1/vsp/findings
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

	findings, total, err := h.DB.ListFindings(r.Context(), claims.TenantID, store.FindingFilter{
		RunID:    q.Get("run_id"),
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
	runID := r.URL.Query().Get("run_id")

	// Auto-select latest DONE run unless scope=all
	if runID == "" && r.URL.Query().Get("scope") != "all" {
		runs, err := h.DB.ListRuns(r.Context(), claims.TenantID, 5, 0)
		if err == nil {
			for _, run := range runs {
				if run.Status == "DONE" {
					runID = run.ID
					break
				}
			}
		}
	}

	s, err := h.DB.FindingsSummary(r.Context(), claims.TenantID, runID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, s)
}
