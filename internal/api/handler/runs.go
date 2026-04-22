package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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
	asynq *asynq.Client
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
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Mode == "" {
		req.Mode = "SAST"
	}
	if req.Profile == "" {
		req.Profile = "FAST"
	}
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
		"SAST":    4,  // bandit + semgrep + codeql + gosec
		"SCA":     3,  // grype + trivy + license
		"SECRETS": 2,  // gitleaks + secretcheck
		"IAC":     2,  // kics + checkov
		"DAST":    3,  // nikto + nuclei + sslscan
		"NETWORK": 1,  // sslscan
		"FULL":    15, // all: sast(4)+sca(3)+secrets(2)+iac(3)+dast(4)
		"FULL_SOC": 16, // FULL + netcap etc (dedup sslscan)
	}[req.Mode]
	if toolsTotal == 0 {
		toolsTotal = 3
	}

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
	limit := queryInt(r, "limit", 20)
	offset := queryInt(r, "offset", 0)

	runs, err := h.DB.ListRuns(r.Context(), claims.TenantID, limit, offset)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []store.Run{}
	}
	jsonOK(w, map[string]any{
		"runs":   runs,
		"limit":  limit,
		"offset": offset,
	})
}

// GET /api/v1/vsp/runs/index  (lightweight for polling)
func (h *Runs) Index(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit := queryInt(r, "limit", 50)
	if limit > 500 {
		limit = 500
	}
	offset := queryInt(r, "offset", 0)
	runs, err := h.DB.ListRuns(r.Context(), claims.TenantID, limit, offset)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	// Return fields needed by FE charts
	type indexRow struct {
		ID         string          `json:"id"`
		RID        string          `json:"rid"`
		Status     string          `json:"status"`
		Mode       string          `json:"mode"`
		Profile    string          `json:"profile"`
		Gate       string          `json:"gate"`
		Posture    string          `json:"posture"`
		Total      int             `json:"total_findings"`
		ToolsDone  int             `json:"tools_done"`
		ToolsTotal int             `json:"tools_total"`
		Summary    json.RawMessage `json:"summary"`
		StartedAt  *time.Time      `json:"started_at"`
		FinishedAt *time.Time      `json:"finished_at"`
		CreatedAt  time.Time       `json:"created_at"`
	}
	rows := make([]indexRow, 0, len(runs))
	for _, run := range runs {
		summ := run.Summary
		if summ == nil {
			summ = json.RawMessage("{}")
		}
		rows = append(rows, indexRow{
			ID:         run.ID,
			RID:        run.RID,
			Status:     run.Status,
			Mode:       run.Mode,
			Profile:    run.Profile,
			Gate:       run.Gate,
			Posture:    run.Posture,
			Total:      run.TotalFindings,
			ToolsDone:  run.ToolsDone,
			ToolsTotal: run.ToolsTotal,
			Summary:    summ,
			StartedAt:  run.StartedAt,
			FinishedAt: run.FinishedAt,
			CreatedAt:  run.CreatedAt,
		})
	}
	jsonOK(w, map[string]any{"runs": rows, "total": len(rows)})
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

// GET /api/v1/vsp/run/{rid}/log
func (h *Runs) Log(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")
	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	// Get findings grouped by tool
	type toolStat struct {
		Tool     string `json:"tool"`
		Total    int    `json:"total"`
		Critical int    `json:"critical"`
		High     int    `json:"high"`
		Medium   int    `json:"medium"`
		Low      int    `json:"low"`
	}
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT tool, COUNT(*),
		       COUNT(*) FILTER (WHERE severity='CRITICAL'),
		       COUNT(*) FILTER (WHERE severity='HIGH'),
		       COUNT(*) FILTER (WHERE severity='MEDIUM'),
		       COUNT(*) FILTER (WHERE severity='LOW')
		FROM findings WHERE run_id=$1 AND tenant_id=$2
		GROUP BY tool ORDER BY COUNT(*) DESC`, run.ID, claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var tools []toolStat
	for rows.Next() {
		var t toolStat
		_ = rows.Scan(&t.Tool, &t.Total, &t.Critical, &t.High, &t.Medium, &t.Low)
		tools = append(tools, t)
	}
	// Build log lines
	type logLine struct {
		TS    string `json:"ts"`
		Tool  string `json:"tool"`
		Level string `json:"level"`
		Msg   string `json:"msg"`
	}
	var lines []logLine
	ts := 0
	fmtTS := func(s int) string {
		return fmt.Sprintf("%02d:%02d:%02d", s/3600, (s%3600)/60, s%60)
	}
	runAny := run
	_ = runAny
	lines = append(lines, logLine{fmtTS(ts), "scanner", "INFO", fmt.Sprintf("Run started: %s", rid)})
	ts++
	lines = append(lines, logLine{fmtTS(ts), "scanner", "INFO", fmt.Sprintf("Mode: %s · Total: %d findings", run.Mode, run.TotalFindings)})
	ts++
	for _, t := range tools {
		lines = append(lines, logLine{fmtTS(ts), t.Tool, "INFO", "Starting scan…"})
		ts++
		if t.Critical > 0 {
			lines = append(lines, logLine{fmtTS(ts), t.Tool, "ERROR", fmt.Sprintf("Found %d CRITICAL findings", t.Critical)})
			ts++
		}
		if t.High > 0 {
			lines = append(lines, logLine{fmtTS(ts), t.Tool, "WARN", fmt.Sprintf("Found %d HIGH findings", t.High)})
			ts++
		}
		if t.Medium > 0 {
			lines = append(lines, logLine{fmtTS(ts), t.Tool, "WARN", fmt.Sprintf("Found %d MEDIUM findings", t.Medium)})
			ts++
		}
		lines = append(lines, logLine{fmtTS(ts), t.Tool, "DONE", fmt.Sprintf("Completed · %d findings", t.Total)})
		ts++
	}
	gl := "INFO"
	if run.Gate == "FAIL" {
		gl = "ERROR"
	} else if run.Gate == "WARN" {
		gl = "WARN"
	}
	score := 0
	var _summ map[string]interface{}
	json.Unmarshal(run.Summary, &_summ)
	if _summ != nil {
		if s, ok := _summ["SCORE"]; ok {
			if v, ok := s.(float64); ok {
				score = int(v)
			}
		}
	}
	lines = append(lines, logLine{fmtTS(ts), "gate", gl,
		fmt.Sprintf("Gate: %s · %d findings · Score: %d/100", run.Gate, run.TotalFindings, score)})
	jsonOK(w, map[string]any{
		"rid": rid, "mode": run.Mode, "status": run.Status, "gate": run.Gate,
		"score": score, "total_findings": run.TotalFindings,
		"lines": lines, "line_count": len(lines),
	})
}

// GET /api/v1/vsp/findings/by-tool?rid=
func (h *Findings) ByTool(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := r.URL.Query().Get("rid")
	runID := r.URL.Query().Get("run_id")
	if rid != "" && runID == "" {
		var id string
		h.DB.Pool().QueryRow(r.Context(),
			`SELECT id::text FROM runs WHERE rid=$1 AND tenant_id=$2 LIMIT 1`,
			rid, claims.TenantID).Scan(&id)
		runID = id
	}
	if runID == "" {
		jsonError(w, "run_id or rid required", http.StatusBadRequest)
		return
	}
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT tool, COUNT(*),
		       COUNT(*) FILTER (WHERE severity='CRITICAL'),
		       COUNT(*) FILTER (WHERE severity='HIGH'),
		       COUNT(*) FILTER (WHERE severity='MEDIUM'),
		       COUNT(*) FILTER (WHERE severity='LOW')
		FROM findings WHERE run_id=$1::uuid AND tenant_id=$2
		GROUP BY tool ORDER BY COUNT(*) DESC`, runID, claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type T struct {
		Tool                               string `json:"tool"`
		Total, Critical, High, Medium, Low int
	}
	var tools []T
	for rows.Next() {
		var t T
		_ = rows.Scan(&t.Tool, &t.Total, &t.Critical, &t.High, &t.Medium, &t.Low)
		tools = append(tools, t)
	}
	if tools == nil {
		tools = []T{}
	}
	jsonOK(w, map[string]any{"tools": tools})
}
