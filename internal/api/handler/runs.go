package handler

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"fmt"
	"net/http"

	"github.com/hibiken/asynq"
	"github.com/vsp/platform/internal/pipeline"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/audit"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Runs struct {
	DB    *store.DB
	asynq  *asynq.Client
}

// POST /api/v1/vsp/run
func (h *Runs) Trigger(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	var req struct {
		Mode    string `json:"mode"`
		Profile string `json:"profile"`
		Src     string `json:"src"`
		URL     string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Mode == "" { req.Mode = "SAST" }
	if req.Profile == "" { req.Profile = "FAST" }
	if req.Src == "" && req.URL == "" {
		jsonError(w, "src or url required", http.StatusBadRequest)
		return
	}
	// Validate src — chặn shell metacharacters
	if req.Src != "" {
		if strings.ContainsAny(req.Src, ";&|`$<>{}\\") {
			jsonError(w, "invalid src: contains illegal characters", http.StatusBadRequest)
			return
		}
		if len(req.Src) > 500 {
			jsonError(w, "src too long", http.StatusBadRequest)
			return
		}
	}
	// Validate URL — chặn SSRF: không cho phép internal/private hosts
	if req.URL != "" {
		if len(req.URL) > 500 {
			jsonError(w, "url too long", http.StatusBadRequest)
			return
		}
		if err := validateScanURL(req.URL); err != nil {
			jsonError(w, "invalid url: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Generate RID
	now := time.Now()
	rid := fmt.Sprintf("RID_VSPGO_RUN_%s_%08x",
		now.Format("20060102_150405"),
		now.UnixNano()&0xFFFFFFFF)

	// Tools total depends on mode
	toolsTotal := map[string]int{
		"SAST":    3,  // bandit + semgrep + codeql
		"SCA":     3,  // grype + trivy + license
		"SECRETS": 2,  // gitleaks + secretcheck
		"IAC":     2,  // kics + checkov
		"DAST":    3,  // nikto + nuclei + sslscan
		"NETWORK": 1,  // sslscan
		"FULL":    14, // all: sast(3)+sca(3)+secrets(2)+iac(2)+dast(3)+network(1)
	}[req.Mode]
	if toolsTotal == 0 { toolsTotal = 3 }

	run, err := h.DB.CreateRun(r.Context(),
		rid, claims.TenantID, req.Mode, req.Profile,
		req.Src, req.URL, toolsTotal)
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	go h.enqueueOrLog(run.RID, claims.TenantID, pipeline.Mode(req.Mode), pipeline.Profile(req.Profile), req.Src, req.URL)
	// Audit: log scan trigger
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) //nolint:gosec // G118: intentional
		defer cancel()
		prevHash, _ := h.DB.GetLastAuditHash(ctx, claims.TenantID)
		e := audit.Entry{
			TenantID: claims.TenantID,
			UserID:   claims.UserID,
			Action:   "SCAN_TRIGGER",
			Resource: run.RID,
			IP:       r.RemoteAddr,
			PrevHash: prevHash,
		}
		e.StoredHash = audit.Hash(e)
		uid := claims.UserID
		h.DB.InsertAudit(ctx, store.AuditWriteParams{TenantID: claims.TenantID, UserID: &uid, Action: "SCAN_TRIGGER", Resource: run.RID, IP: r.RemoteAddr, PrevHash: prevHash})
	}()




	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, map[string]any{
		"rid":         run.RID,
		"id":          run.ID,
		"status":      run.Status,
		"mode":        run.Mode,
		"profile":     run.Profile,
		"tools_total": run.ToolsTotal,
		"created_at":  run.CreatedAt,
		"message":     "run queued — poll GET /api/v1/vsp/run/" + run.RID,
	})
}

// GET /api/v1/vsp/run/latest
func (h *Runs) Latest(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	run, err := h.DB.GetLatestRun(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if run == nil {
		jsonError(w, "no runs found", http.StatusNotFound)
		return
	}
	jsonOK(w, run)
}

// GET /api/v1/vsp/run/{rid}
func (h *Runs) Get(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")
	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	jsonOK(w, run)
}

// GET /api/v1/vsp/runs
func (h *Runs) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit  := queryInt(r, "limit", 20)
	offset := queryInt(r, "offset", 0)

	runs, err := h.DB.ListRuns(r.Context(), claims.TenantID, limit, offset)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if runs == nil { runs = []store.Run{} }
	jsonOK(w, map[string]any{
		"runs":   runs,
		"limit":  limit,
		"offset": offset,
	})
}

// GET /api/v1/vsp/runs/index  (lightweight for polling)
func (h *Runs) Index(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runs, err := h.DB.ListRuns(r.Context(), claims.TenantID, 50, 0)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	// Return minimal fields only
	type indexRow struct {
		RID        string          `json:"rid"`
		Status     string          `json:"status"`
		Mode       string          `json:"mode"`
		Profile    string          `json:"profile"`
		Gate       string          `json:"gate"`
		Total      int             `json:"total"`
		ToolsDone  int             `json:"tools_done"`
		ToolsTotal int             `json:"tools_total"`
		Summary    json.RawMessage `json:"summary"`
		CreatedAt  time.Time       `json:"created_at"`
	}
	rows := make([]indexRow, 0, len(runs))
	for _, run := range runs {
		summ := run.Summary
		if summ == nil { summ = json.RawMessage("{}") }
		rows = append(rows, indexRow{
			RID:        run.RID,
			Status:     run.Status,
			Mode:       run.Mode,
			Profile:    run.Profile,
			Gate:       run.Gate,
			Total:      run.TotalFindings,
			ToolsDone:  run.ToolsDone,
			ToolsTotal: run.ToolsTotal,
			Summary:    summ,
			CreatedAt:  run.CreatedAt,
		})
	}
	jsonOK(w, map[string]any{"runs": rows})
}

// POST /api/v1/vsp/run/{rid}/cancel
func (h *Runs) Cancel(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")
	if err := h.DB.UpdateRunStatus(r.Context(), claims.TenantID, rid, "CANCELLED", 0); err != nil {
		jsonError(w, "cancel failed", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"rid": rid, "status": "CANCELLED"})
}

