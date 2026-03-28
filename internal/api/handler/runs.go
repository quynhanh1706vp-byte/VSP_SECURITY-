package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hibiken/asynq"
	"time"

	"github.com/go-chi/chi/v5"
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

	// Generate RID
	now := time.Now()
	rid := fmt.Sprintf("RID_VSPGO_RUN_%s_%08x",
		now.Format("20060102_150405"),
		now.UnixNano()&0xFFFFFFFF)

	// Tools total depends on mode
	toolsTotal := map[string]int{
		"SAST": 3, "SCA": 2, "SECRETS": 1,
		"IAC": 1,  "DAST": 1, "FULL": 8,
	}[req.Mode]
	if toolsTotal == 0 { toolsTotal = 3 }

	run, err := h.DB.CreateRun(r.Context(),
		rid, claims.TenantID, req.Mode, req.Profile,
		req.Src, req.URL, toolsTotal)
	if err != nil {
		jsonError(w, "create run failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// TODO: enqueue to asynq scanner worker
	// task, _ := asynq.NewTask(pipeline.TaskTypeScan, payload)
	// client.Enqueue(task)

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
		RID        string     `json:"rid"`
		Status     string     `json:"status"`
		Mode       string     `json:"mode"`
		Gate       string     `json:"gate"`
		Total      int        `json:"total"`
		ToolsDone  int        `json:"tools_done"`
		ToolsTotal int        `json:"tools_total"`
		CreatedAt  time.Time  `json:"created_at"`
	}
	rows := make([]indexRow, 0, len(runs))
	for _, run := range runs {
		rows = append(rows, indexRow{
			RID:        run.RID,
			Status:     run.Status,
			Mode:       run.Mode,
			Gate:       run.Gate,
			Total:      run.TotalFindings,
			ToolsDone:  run.ToolsDone,
			ToolsTotal: run.ToolsTotal,
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

