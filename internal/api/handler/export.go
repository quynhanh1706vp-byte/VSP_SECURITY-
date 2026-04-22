package handler

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/report"
	"github.com/vsp/platform/internal/store"
)

type Export struct {
	DB *store.DB
}

// GET /api/v1/export/sarif/{rid}
func (h *Export) SARIF(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")
	if !validateRID(rid) {
		jsonError(w, "invalid rid", http.StatusBadRequest)
		return
	}

	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	findings, _, _ := h.DB.ListFindings(r.Context(), claims.TenantID,
		store.FindingFilter{RunID: run.ID, Limit: 5000})

	doc := report.BuildSARIF(*run, findings)
	data, _ := report.SARIFToJSON(doc)

	w.Header().Set("Content-Type", "application/sarif+json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=vsp-%s.sarif", rid))
	_, _ = w.Write(data) // #nosec G705 -- SARIF JSON export, Content-Type application/json
}

// GET /api/v1/export/csv/{rid}
func (h *Export) CSV(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")

	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	findings, _, _ := h.DB.ListFindings(r.Context(), claims.TenantID,
		store.FindingFilter{RunID: run.ID, Limit: 10000})

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=vsp-%s.csv", rid))

	cw := csv.NewWriter(w)
	cw.Write([]string{"severity", "tool", "rule_id", "message", "path", "line", "cwe", "fix_signal", "created_at"})
	for _, f := range findings {
		cw.Write([]string{
			f.Severity, f.Tool, f.RuleID, f.Message,
			f.Path, fmt.Sprintf("%d", f.LineNum),
			f.CWE, f.FixSignal, f.CreatedAt.Format(time.RFC3339),
		})
	}
	cw.Flush()
}

// GET /api/v1/export/json/{rid}
func (h *Export) JSON(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")

	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	runFindings, total, _ := h.DB.ListFindings(r.Context(), claims.TenantID,
		store.FindingFilter{RunID: run.ID, Limit: 10000})
	if runFindings == nil {
		runFindings = []store.Finding{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=vsp-%s.json", rid))

	_ = json.NewEncoder(w).Encode(map[string]any{
		"run":         run,
		"findings":    runFindings,
		"total":       total,
		"exported_at": time.Now(),
	})
}
