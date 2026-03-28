#!/usr/bin/env bash
# ================================================================
# VSP Go — phase3_eg.sh
# Phase 3: Scanner worker (E) + SOC Shell dashboard (G)
# Chay tu ~/Data/GOLANG_VSP
# ================================================================
set -e
echo ">>> Phase 3: Scanner worker + SOC Shell"
mkdir -p internal/pipeline internal/api/handler cmd/scanner cmd/soc-shell static

# cmd/scanner/main.go
mkdir -p "cmd/scanner"
cat > 'cmd/scanner/main.go' << 'VSP3CMD_SCANNER_MAIN_GO'
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/vsp/platform/internal/pipeline"
	"github.com/vsp/platform/internal/store"
)

func main() {
	viper.SetDefault("redis.addr", "localhost:6379")
	viper.SetDefault("database.url", "postgres://vsp:vsp@localhost:5432/vsp_go")
	viper.SetDefault("scanner.concurrency", 3)
	viper.SetDefault("log.level", "info")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	viper.ReadInConfig()

	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	ctx := context.Background()
	db, err := store.New(ctx, viper.GetString("database.url"))
	if err != nil {
		log.Fatal().Err(err).Msg("db connect failed")
	}
	defer db.Close()

	handler := pipeline.NewScanHandler(db)

	srv := asynq.NewServer(
		asynq.RedisClientOpt{Addr: viper.GetString("redis.addr")},
		asynq.Config{
			Concurrency: viper.GetInt("scanner.concurrency"),
			Queues:      map[string]int{"critical": 6, "default": 3, "low": 1},
			ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
				log.Error().Err(err).Str("task", task.Type()).Msg("task failed")
			}),
		},
	)

	mux := asynq.NewServeMux()
	mux.HandleFunc(pipeline.TaskTypeScan, handler.ProcessTask)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-quit; srv.Shutdown() }()

	log.Info().
		Str("redis", viper.GetString("redis.addr")).
		Int("concurrency", viper.GetInt("scanner.concurrency")).
		Msg("VSP Scanner worker starting")

	if err := srv.Run(mux); err != nil {
		log.Fatal().Err(err).Msg("worker failed")
	}
}
VSP3CMD_SCANNER_MAIN_GO

# cmd/soc-shell/main.go
mkdir -p "cmd/soc-shell"
cat > 'cmd/soc-shell/main.go' << 'VSP3CMD_SOC_SHELL_MAIN_GO'
package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

func main() {
	viper.SetDefault("server.shell_port", 8922)
	viper.SetDefault("server.gateway_port", 8921)
	viper.SetDefault("log.level", "info")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	viper.ReadInConfig()

	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	shellPort   := viper.GetInt("server.shell_port")
	gatewayPort := viper.GetInt("server.gateway_port")
	gatewayURL, _ := url.Parse(fmt.Sprintf("http://localhost:%d", gatewayPort))
	proxy := httputil.NewSingleHostReverseProxy(gatewayURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"soc-shell","port":%d}`, shellPort)
	})
	// Serve static files, fallback to index.html for SPA
	fs := http.FileServer(http.Dir("./static"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			_, err := os.Stat("./static" + r.URL.Path)
			if os.IsNotExist(err) {
				// SPA fallback
				http.ServeFile(w, r, "./static/index.html")
				return
			}
		}
		fs.ServeHTTP(w, r)
	})

	addr := fmt.Sprintf(":%d", shellPort)
	log.Info().
		Str("addr", addr).
		Int("gateway", gatewayPort).
		Str("static", "./static").
		Msg("VSP SOC Shell starting")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal().Err(err).Msg("shell server failed")
	}
}
VSP3CMD_SOC_SHELL_MAIN_GO

# internal/api/handler/internal.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/internal.go' << 'VSP3INTERNAL_API_HANDLER_INTERNAL_GO'
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/gate"
	"github.com/vsp/platform/internal/scanner"
	"github.com/vsp/platform/internal/store"
)

// InternalScan handles callbacks from the scanner worker.
// POST /internal/scan/complete
type InternalScan struct {
	DB *store.DB
}

type ScanCompletePayload struct {
	RID        string           `json:"rid"`
	TenantID   string           `json:"tenant_id"`
	Findings   []store.Finding  `json:"findings"`
	ToolErrors map[string]string `json:"tool_errors"`
	DurationMs int64            `json:"duration_ms"`
}

func (h *InternalScan) Complete(w http.ResponseWriter, r *http.Request) {
	var payload ScanCompletePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		jsonError(w, "invalid payload", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// 1. Insert findings
	if err := h.DB.InsertFindingsBatch(ctx, payload.Findings); err != nil {
		log.Error().Err(err).Str("rid", payload.RID).Msg("insert findings failed")
		jsonError(w, "insert findings failed", http.StatusInternalServerError)
		return
	}

	// 2. Build summary
	sev := make(map[string]int)
	hasSecrets := false
	for _, f := range payload.Findings {
		sev[f.Severity]++
		if f.Tool == "gitleaks" { hasSecrets = true }
	}
	s := scanner.Summary{
		Critical:   sev["CRITICAL"],
		High:       sev["HIGH"],
		Medium:     sev["MEDIUM"],
		Low:        sev["LOW"],
		Info:       sev["INFO"],
		HasSecrets: hasSecrets,
	}

	// 3. Evaluate gate
	rule := gate.DefaultRule()
	result := gate.Evaluate(rule, s)

	// 4. Build summary JSON
	summaryJSON, _ := json.Marshal(map[string]int{
		"CRITICAL": s.Critical,
		"HIGH":     s.High,
		"MEDIUM":   s.Medium,
		"LOW":      s.Low,
		"INFO":     s.Info,
	})

	// 5. Update run record
	if err := h.DB.UpdateRunResult(ctx, payload.TenantID, payload.RID,
		string(result.Decision), result.Posture,
		len(payload.Findings), summaryJSON); err != nil {
		log.Error().Err(err).Str("rid", payload.RID).Msg("update run result failed")
	}

	log.Info().
		Str("rid", payload.RID).
		Int("findings", len(payload.Findings)).
		Str("gate", string(result.Decision)).
		Str("posture", result.Posture).
		Msg("scan complete")

	jsonOK(w, map[string]any{
		"ok":       true,
		"rid":      payload.RID,
		"gate":     result.Decision,
		"posture":  result.Posture,
		"score":    result.Score,
		"findings": len(payload.Findings),
	})
}
VSP3INTERNAL_API_HANDLER_INTERNAL_GO

# internal/api/handler/runs.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/runs.go' << 'VSP3INTERNAL_API_HANDLER_RUNS_GO'
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/hibiken/asynq"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/pipeline"
	"github.com/vsp/platform/internal/store"
)

type Runs struct {
	DB    *store.DB
	asynq *asynq.Client // optional — nil = no worker
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

	now := time.Now()
	rid := fmt.Sprintf("RID_VSPGO_RUN_%s_%08x",
		now.Format("20060102_150405"),
		now.UnixNano()&0xFFFFFFFF)

	toolsTotal := map[string]int{
		"SAST": 3, "SCA": 2, "SECRETS": 1,
		"IAC": 1, "DAST": 1, "FULL": 8,
	}[req.Mode]
	if toolsTotal == 0 { toolsTotal = 3 }

	run, err := h.DB.CreateRun(r.Context(),
		rid, claims.TenantID, req.Mode, req.Profile,
		req.Src, req.URL, toolsTotal)
	if err != nil {
		jsonError(w, "create run failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Enqueue to scanner worker (non-blocking)
	go h.enqueueOrLog(rid, claims.TenantID,
		pipeline.Mode(req.Mode), pipeline.Profile(req.Profile),
		req.Src, req.URL)

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
	if err != nil || run == nil {
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
	jsonOK(w, map[string]any{"runs": runs, "limit": limit, "offset": offset})
}

// GET /api/v1/vsp/runs/index
func (h *Runs) Index(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runs, err := h.DB.ListRuns(r.Context(), claims.TenantID, 50, 0)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	type row struct {
		RID        string    `json:"rid"`
		Status     string    `json:"status"`
		Mode       string    `json:"mode"`
		Gate       string    `json:"gate"`
		Total      int       `json:"total"`
		ToolsDone  int       `json:"tools_done"`
		ToolsTotal int       `json:"tools_total"`
		CreatedAt  time.Time `json:"created_at"`
	}
	rows := make([]row, 0, len(runs))
	for _, rn := range runs {
		rows = append(rows, row{
			RID: rn.RID, Status: rn.Status, Mode: rn.Mode,
			Gate: rn.Gate, Total: rn.TotalFindings,
			ToolsDone: rn.ToolsDone, ToolsTotal: rn.ToolsTotal,
			CreatedAt: rn.CreatedAt,
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
VSP3INTERNAL_API_HANDLER_RUNS_GO

# internal/api/handler/runs_enqueue.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/runs_enqueue.go' << 'VSP3INTERNAL_API_HANDLER_RUNS_ENQUEUE_GO'
package handler

import (
	"github.com/hibiken/asynq"
	"github.com/vsp/platform/internal/pipeline"
	"github.com/rs/zerolog/log"
)

// SetAsynqClient wires an asynq client into the Runs handler so that
// POST /vsp/run actually enqueues the job to the scanner worker.
// Call this from main() after creating the handler.
func (h *Runs) SetAsynqClient(client *asynq.Client) {
	h.asynq = client
}

// enqueueOrLog enqueues the scan job if asynq is wired, else logs a warning.
func (h *Runs) enqueueOrLog(rid, tenantID string, mode pipeline.Mode, profile pipeline.Profile, src, url string) {
	if h.asynq == nil {
		log.Warn().Str("rid", rid).Msg("asynq not configured — run scanner binary separately")
		return
	}
	payload := pipeline.JobPayload{
		RID: rid, TenantID: tenantID,
		Mode: mode, Profile: profile,
		Src: src, TargetURL: url,
	}
	if err := pipeline.EnqueueScan(h.asynq, payload); err != nil {
		log.Error().Err(err).Str("rid", rid).Msg("enqueue failed")
	} else {
		log.Info().Str("rid", rid).Msg("scan enqueued")
	}
}
VSP3INTERNAL_API_HANDLER_RUNS_ENQUEUE_GO

# internal/pipeline/worker.go
mkdir -p "internal/pipeline"
cat > 'internal/pipeline/worker.go' << 'VSP3INTERNAL_PIPELINE_WORKER_GO'
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/gate"
	"github.com/vsp/platform/internal/scanner"
	"github.com/vsp/platform/internal/store"
)

const TaskTypeScan = "scan:run"

// NewScanTask creates an asynq task for a scan job.
func NewScanTask(payload JobPayload) (*asynq.Task, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TaskTypeScan, b,
		asynq.MaxRetry(2),
		asynq.Timeout(20*time.Minute),
	), nil
}

// ScanHandler is the asynq task handler that runs the actual scan.
type ScanHandler struct {
	DB       *store.DB
	Exec     *Executor
}

func NewScanHandler(db *store.DB) *ScanHandler {
	return &ScanHandler{
		DB: db,
		Exec: &Executor{
			OnProgress: func(tool string, done, total, findings int) {
				log.Info().
					Str("tool", tool).
					Int("done", done).Int("total", total).
					Int("findings", findings).
					Msg("tool done")
			},
		},
	}
}

func (h *ScanHandler) ProcessTask(ctx context.Context, t *asynq.Task) error {
	var payload JobPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	log.Info().Str("rid", payload.RID).Str("mode", string(payload.Mode)).Msg("scan started")

	// Mark RUNNING
	h.DB.UpdateRunStatus(ctx, payload.TenantID, payload.RID, "RUNNING", 0)

	// Execute
	result, err := h.Exec.Execute(ctx, payload)
	if err != nil {
		h.DB.UpdateRunStatus(ctx, payload.TenantID, payload.RID, "FAILED", 0)
		return err
	}

	// Persist findings
	dbFindings := make([]store.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		raw, _ := json.Marshal(f.Raw)
		dbFindings = append(dbFindings, store.Finding{
			TenantID:  payload.TenantID,
			Tool:      f.Tool,
			Severity:  string(f.Severity),
			RuleID:    f.RuleID,
			Message:   f.Message,
			Path:      f.Path,
			LineNum:   f.Line,
			CWE:       f.CWE,
			FixSignal: f.FixSignal,
			Raw:       raw,
		})
	}

	// Get run ID for findings FK
	run, _ := h.DB.GetRunByRID(ctx, payload.TenantID, payload.RID)
	if run != nil {
		for i := range dbFindings {
			dbFindings[i].RunID = run.ID
		}
	}
	h.DB.InsertFindings(ctx, dbFindings)

	// Compute gate + posture
	s := result.Summary
	policyRule := gate.DefaultRule()
	rules, _ := h.DB.ListPolicyRules(ctx, payload.TenantID)
	if len(rules) > 0 {
		r0 := rules[0]
		policyRule = gate.PolicyRule{
			FailOn: r0.FailOn, MinScore: r0.MinScore, MaxHigh: r0.MaxHigh,
			BlockSecrets: r0.BlockSecrets, BlockCritical: r0.BlockCritical,
		}
	}
	eval := gate.Evaluate(policyRule, s)

	summaryJSON, _ := json.Marshal(map[string]int{
		"CRITICAL": s.Critical, "HIGH": s.High,
		"MEDIUM": s.Medium, "LOW": s.Low, "INFO": s.Info,
	})

	h.DB.UpdateRunResult(ctx, payload.TenantID, payload.RID,
		string(eval.Decision), eval.Posture,
		len(result.Findings), summaryJSON)

	// Write tool errors as audit
	for tool, terr := range result.ToolErrors {
		log.Warn().Str("rid", payload.RID).Str("tool", tool).Err(terr).Msg("tool error")
	}

	log.Info().
		Str("rid", payload.RID).
		Str("gate", string(eval.Decision)).
		Str("posture", eval.Posture).
		Int("findings", len(result.Findings)).
		Dur("duration", result.Duration).
		Msg("scan complete")

	return nil
}

// EnqueueScan enqueues a scan task. Called by the gateway trigger handler.
func EnqueueScan(client *asynq.Client, payload JobPayload) error {
	task, err := NewScanTask(payload)
	if err != nil {
		return err
	}
	_, err = client.Enqueue(task, asynq.Queue("default"))
	return err
}

// ScannerSummaryFromStore converts store.FindingSummary to scanner.Summary.
func ScannerSummaryFromStore(s *store.FindingSummary) scanner.Summary {
	if s == nil { return scanner.Summary{} }
	return scanner.Summary{
		Critical: s.Critical, High: s.High,
		Medium: s.Medium, Low: s.Low, Info: s.Info,
	}
}
VSP3INTERNAL_PIPELINE_WORKER_GO

# internal/store/findings_write.go
mkdir -p "internal/store"
cat > 'internal/store/findings_write.go' << 'VSP3INTERNAL_STORE_FINDINGS_WRITE_GO'
package store

import (
	"context"
	"fmt"
)

// InsertFindingsBatch inserts findings efficiently using pgx CopyFrom.
func (db *DB) InsertFindingsBatch(ctx context.Context, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	for _, f := range findings {
		_, err := db.pool.Exec(ctx,
			`INSERT INTO findings
			 (run_id, tenant_id, tool, severity, rule_id, message, path, line_num, cwe, fix_signal, raw)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			 ON CONFLICT DO NOTHING`,
			f.RunID, f.TenantID, f.Tool, f.Severity,
			f.RuleID, f.Message, f.Path, f.LineNum,
			f.CWE, f.FixSignal, f.Raw)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", f.RuleID, err)
		}
	}
	return nil
}
VSP3INTERNAL_STORE_FINDINGS_WRITE_GO

# static/index.html
mkdir -p "static"
cat > 'static/index.html' << 'VSP3STATIC_INDEX_HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VSP Security Platform</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
  /* Nav */
  .nav { background: #1e293b; border-bottom: 1px solid #334155; padding: 0 24px;
         display: flex; align-items: center; gap: 32px; height: 56px; }
  .nav-brand { color: #38bdf8; font-weight: 700; font-size: 18px; letter-spacing: 1px; }
  .nav-tabs { display: flex; gap: 4px; }
  .tab { padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 13px;
         color: #94a3b8; border: none; background: none; transition: all .15s; }
  .tab:hover { color: #e2e8f0; background: #334155; }
  .tab.active { color: #38bdf8; background: #0f2744; }
  .nav-right { margin-left: auto; display: flex; align-items: center; gap: 12px; }
  .badge { padding: 3px 10px; border-radius: 99px; font-size: 12px; font-weight: 600; }
  .badge-green { background: #14532d; color: #4ade80; }
  .badge-red   { background: #7f1d1d; color: #fca5a5; }
  .badge-yellow{ background: #713f12; color: #fbbf24; }
  /* Layout */
  .main { padding: 24px; max-width: 1400px; margin: 0 auto; }
  /* Cards */
  .grid4 { display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 24px; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; }
  .card-title { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: .05em; margin-bottom: 8px; }
  .card-value { font-size: 32px; font-weight: 700; }
  .card-sub { font-size: 12px; color: #64748b; margin-top: 4px; }
  .c-crit { color: #f87171; } .c-high { color: #fb923c; }
  .c-med  { color: #fbbf24; } .c-low  { color: #4ade80; }
  .c-pass { color: #4ade80; } .c-warn { color: #fbbf24; } .c-fail { color: #f87171; }
  /* Table */
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; color: #64748b; border-bottom: 1px solid #334155;
       font-size: 11px; text-transform: uppercase; }
  td { padding: 10px 12px; border-bottom: 1px solid #1e293b; }
  tr:hover td { background: #1e293b; }
  /* Buttons */
  .btn { padding: 8px 16px; border-radius: 8px; border: none; cursor: pointer;
         font-size: 13px; font-weight: 500; transition: all .15s; }
  .btn-primary { background: #2563eb; color: #fff; }
  .btn-primary:hover { background: #1d4ed8; }
  .btn-sm { padding: 4px 10px; font-size: 12px; border-radius: 6px; }
  .btn-outline { background: none; border: 1px solid #334155; color: #94a3b8; }
  .btn-outline:hover { border-color: #64748b; color: #e2e8f0; }
  /* Login */
  .login-wrap { display: flex; align-items: center; justify-content: center;
                min-height: 100vh; background: #0f172a; }
  .login-card { background: #1e293b; border: 1px solid #334155; border-radius: 16px;
                padding: 40px; width: 360px; }
  .login-title { font-size: 22px; font-weight: 700; color: #38bdf8; margin-bottom: 24px; text-align: center; }
  .form-group { margin-bottom: 16px; }
  .form-label { font-size: 12px; color: #94a3b8; margin-bottom: 6px; display: block; }
  .form-input { width: 100%; padding: 10px 12px; background: #0f172a; border: 1px solid #334155;
                border-radius: 8px; color: #e2e8f0; font-size: 14px; outline: none; }
  .form-input:focus { border-color: #38bdf8; }
  .error-msg { color: #f87171; font-size: 13px; margin-top: 8px; text-align: center; }
  /* Section header */
  .section-head { display: flex; align-items: center; justify-content: space-between;
                  margin-bottom: 16px; }
  .section-title { font-size: 16px; font-weight: 600; color: #f1f5f9; }
  /* Status pill */
  .pill { padding: 2px 8px; border-radius: 99px; font-size: 11px; font-weight: 600; }
  .pill-queued  { background: #1e3a5f; color: #60a5fa; }
  .pill-running { background: #1c3a2a; color: #34d399; }
  .pill-done    { background: #14532d; color: #4ade80; }
  .pill-failed  { background: #7f1d1d; color: #fca5a5; }
  .pill-pass    { background: #14532d; color: #4ade80; }
  .pill-warn    { background: #713f12; color: #fbbf24; }
  .pill-fail    { background: #7f1d1d; color: #fca5a5; }
  /* Trigger form */
  .trigger-form { display: flex; gap: 8px; align-items: flex-end; flex-wrap: wrap; }
  .trigger-form select, .trigger-form input {
    padding: 8px 12px; background: #0f172a; border: 1px solid #334155;
    border-radius: 8px; color: #e2e8f0; font-size: 13px; outline: none; }
  .trigger-form select:focus, .trigger-form input:focus { border-color: #38bdf8; }
  /* Spinner */
  @keyframes spin { to { transform: rotate(360deg); } }
  .spin { animation: spin .8s linear infinite; display: inline-block; }
  /* Panel visibility */
  .panel { display: none; }
  .panel.active { display: block; }
</style>
</head>
<body>

<!-- Login Screen -->
<div id="loginScreen" class="login-wrap">
  <div class="login-card">
    <div class="login-title">⬡ VSP Platform</div>
    <div class="form-group">
      <label class="form-label">Email</label>
      <input id="loginEmail" class="form-input" type="email" value="admin@vsp.local" placeholder="admin@vsp.local">
    </div>
    <div class="form-group">
      <label class="form-label">Password</label>
      <input id="loginPassword" class="form-input" type="password" value="admin123" placeholder="password">
    </div>
    <button class="btn btn-primary" style="width:100%;margin-top:8px" onclick="doLogin()">Sign In</button>
    <div id="loginError" class="error-msg"></div>
  </div>
</div>

<!-- Main App -->
<div id="appScreen" style="display:none">
  <nav class="nav">
    <span class="nav-brand">⬡ VSP</span>
    <div class="nav-tabs">
      <button class="tab active" onclick="showPanel('dashboard',this)">Dashboard</button>
      <button class="tab" onclick="showPanel('runs',this)">Runs</button>
      <button class="tab" onclick="showPanel('findings',this)">Findings</button>
      <button class="tab" onclick="showPanel('policy',this)">Policy</button>
      <button class="tab" onclick="showPanel('audit',this)">Audit</button>
    </div>
    <div class="nav-right">
      <span id="gateWidget" class="badge badge-green">PASS</span>
      <span id="userWidget" class="badge" style="background:#1e293b;color:#94a3b8">—</span>
      <button class="btn btn-sm btn-outline" onclick="doLogout()">Logout</button>
    </div>
  </nav>

  <div class="main">

    <!-- Dashboard -->
    <div id="panel-dashboard" class="panel active">
      <div class="grid4">
        <div class="card">
          <div class="card-title">Security Score</div>
          <div class="card-value c-pass" id="d-score">—</div>
          <div class="card-sub">out of 100</div>
        </div>
        <div class="card">
          <div class="card-title">Posture Grade</div>
          <div class="card-value c-pass" id="d-posture">—</div>
          <div class="card-sub">latest run</div>
        </div>
        <div class="card">
          <div class="card-title">Total Runs</div>
          <div class="card-value" id="d-runs">—</div>
          <div class="card-sub">all time</div>
        </div>
        <div class="card">
          <div class="card-title">Gate Decision</div>
          <div class="card-value" id="d-gate">—</div>
          <div class="card-sub">latest</div>
        </div>
      </div>
      <div class="grid4">
        <div class="card">
          <div class="card-title">Critical</div>
          <div class="card-value c-crit" id="d-critical">0</div>
        </div>
        <div class="card">
          <div class="card-title">High</div>
          <div class="card-value c-high" id="d-high">0</div>
        </div>
        <div class="card">
          <div class="card-title">Medium</div>
          <div class="card-value c-med" id="d-medium">0</div>
        </div>
        <div class="card">
          <div class="card-title">Low</div>
          <div class="card-value c-low" id="d-low">0</div>
        </div>
      </div>
      <div class="card">
        <div class="section-head">
          <span class="section-title">Recent Runs</span>
          <button class="btn btn-sm btn-primary" onclick="showPanel('runs',null);showTrigger()">+ New Scan</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>RID</th><th>Mode</th><th>Status</th><th>Gate</th><th>Findings</th><th>Created</th></tr></thead>
            <tbody id="d-runs-table"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Runs -->
    <div id="panel-runs" class="panel">
      <div class="card" style="margin-bottom:16px">
        <div class="section-head">
          <span class="section-title">Trigger New Scan</span>
        </div>
        <div class="trigger-form">
          <div>
            <div class="form-label">Mode</div>
            <select id="scanMode">
              <option>SAST</option><option>SCA</option><option>SECRETS</option>
              <option>IAC</option><option>DAST</option><option>FULL</option>
            </select>
          </div>
          <div>
            <div class="form-label">Profile</div>
            <select id="scanProfile">
              <option>FAST</option><option>EXT</option><option>FULL</option>
            </select>
          </div>
          <div style="flex:1;min-width:200px">
            <div class="form-label">Source Path</div>
            <input id="scanSrc" type="text" placeholder="/path/to/code" style="width:100%">
          </div>
          <button class="btn btn-primary" onclick="triggerScan()">Run Scan</button>
        </div>
        <div id="triggerMsg" style="margin-top:10px;font-size:13px;color:#4ade80"></div>
      </div>
      <div class="card">
        <div class="section-head">
          <span class="section-title">Run History</span>
          <button class="btn btn-sm btn-outline" onclick="loadRuns()">↻ Refresh</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>RID</th><th>Mode</th><th>Profile</th><th>Status</th><th>Gate</th>
              <th>Findings</th><th>Tools</th><th>Created</th></tr></thead>
            <tbody id="runs-table"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Findings -->
    <div id="panel-findings" class="panel">
      <div class="card" style="margin-bottom:16px">
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <select id="filterSev" onchange="loadFindings()" style="padding:6px 10px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:13px">
            <option value="">All severities</option>
            <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
          </select>
          <select id="filterTool" onchange="loadFindings()" style="padding:6px 10px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:13px">
            <option value="">All tools</option>
            <option>bandit</option><option>semgrep</option><option>grype</option>
            <option>trivy</option><option>gitleaks</option><option>kics</option>
          </select>
          <input id="filterQ" type="text" placeholder="Search…" onkeyup="if(event.key==='Enter')loadFindings()"
            style="padding:6px 10px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:13px;width:200px">
          <button class="btn btn-sm btn-primary" onclick="loadFindings()">Search</button>
          <span id="findings-count" style="color:#64748b;font-size:13px;margin-left:auto"></span>
        </div>
      </div>
      <div class="card">
        <div class="table-wrap">
          <table>
            <thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Message</th><th>Path</th><th>Line</th><th>CWE</th></tr></thead>
            <tbody id="findings-table"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Policy -->
    <div id="panel-policy" class="panel">
      <div class="card" style="margin-bottom:16px">
        <div class="section-head">
          <span class="section-title">Gate Evaluation</span>
          <button class="btn btn-primary btn-sm" onclick="runEval()">Evaluate Latest Run</button>
        </div>
        <div id="eval-result" style="margin-top:12px;font-size:14px"></div>
      </div>
      <div class="card">
        <div class="section-head">
          <span class="section-title">Policy Rules</span>
          <button class="btn btn-sm btn-outline" onclick="loadRules()">↻ Refresh</button>
        </div>
        <div id="rules-list" style="color:#64748b;font-size:13px">Loading…</div>
      </div>
    </div>

    <!-- Audit -->
    <div id="panel-audit" class="panel">
      <div class="card" style="margin-bottom:16px">
        <div class="section-head">
          <span class="section-title">Hash Chain Integrity</span>
          <button class="btn btn-sm btn-primary" onclick="verifyAudit()">Verify Chain</button>
        </div>
        <div id="verify-result" style="font-size:14px;color:#64748b">Click verify to check chain integrity.</div>
      </div>
      <div class="card">
        <div class="section-head">
          <span class="section-title">Audit Log</span>
          <button class="btn btn-sm btn-outline" onclick="loadAudit()">↻ Refresh</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Seq</th><th>Action</th><th>Resource</th><th>IP</th><th>Time</th><th>Hash</th></tr></thead>
            <tbody id="audit-table"></tbody>
          </table>
        </div>
      </div>
    </div>

  </div><!-- main -->
</div><!-- appScreen -->

<script>
const API = '/api/v1'
let TOKEN = localStorage.getItem('vsp_token') || ''
let USER  = JSON.parse(localStorage.getItem('vsp_user') || '{}')

// ── Auth ────────────────────────────────────────────────────────────────────
async function doLogin() {
  const email    = document.getElementById('loginEmail').value
  const password = document.getElementById('loginPassword').value
  const err      = document.getElementById('loginError')
  try {
    const r = await api('POST', '/auth/login', {email, password}, true)
    TOKEN = r.token
    USER  = {email: r.email, role: r.role, tenant_id: r.tenant_id}
    localStorage.setItem('vsp_token', TOKEN)
    localStorage.setItem('vsp_user', JSON.stringify(USER))
    showApp()
  } catch(e) {
    err.textContent = 'Login failed: ' + (e.message || 'check credentials')
  }
}

function doLogout() {
  api('POST', '/auth/logout').catch(()=>{})
  localStorage.removeItem('vsp_token')
  localStorage.removeItem('vsp_user')
  TOKEN = ''
  document.getElementById('appScreen').style.display = 'none'
  document.getElementById('loginScreen').style.display = 'flex'
}

function showApp() {
  document.getElementById('loginScreen').style.display = 'none'
  document.getElementById('appScreen').style.display   = 'block'
  document.getElementById('userWidget').textContent = USER.email + ' [' + (USER.role||'') + ']'
  loadDashboard()
  startPolling()
}

// ── API helper ────────────────────────────────────────────────────────────────
async function api(method, path, body, noAuth) {
  const opts = { method, headers: {'Content-Type':'application/json'} }
  if (!noAuth && TOKEN) opts.headers['Authorization'] = 'Bearer ' + TOKEN
  if (body) opts.body = JSON.stringify(body)
  const r = await fetch(API + path, opts)
  if (r.status === 401) { doLogout(); throw new Error('session expired') }
  const data = await r.json()
  if (!r.ok) throw new Error(data.error || r.statusText)
  return data
}

// ── Navigation ────────────────────────────────────────────────────────────────
function showPanel(name, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'))
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'))
  document.getElementById('panel-' + name).classList.add('active')
  if (btn) btn.classList.add('active')
  else document.querySelectorAll('.tab').forEach(t => {
    if (t.textContent.toLowerCase() === name) t.classList.add('active')
  })
  if (name === 'runs')     loadRuns()
  if (name === 'findings') loadFindings()
  if (name === 'audit')    loadAudit()
  if (name === 'policy')   loadRules()
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const [summary, posture, runs] = await Promise.all([
      api('GET', '/vsp/findings/summary'),
      api('GET', '/vsp/posture/latest').catch(()=>null),
      api('GET', '/vsp/runs/index'),
    ])
    document.getElementById('d-critical').textContent = summary.critical
    document.getElementById('d-high').textContent     = summary.high
    document.getElementById('d-medium').textContent   = summary.medium
    document.getElementById('d-low').textContent      = summary.low
    if (posture) {
      const sc = document.getElementById('d-score')
      sc.textContent = posture.score
      sc.className   = 'card-value ' + (posture.score >= 80 ? 'c-pass' : posture.score >= 50 ? 'c-warn' : 'c-fail')
      document.getElementById('d-posture').textContent = posture.grade
      const gw = document.getElementById('d-gate')
      const rg = posture.grade
      gw.textContent = rg
      // nav badge
      const nb = document.getElementById('gateWidget')
    }
    const runList = runs.runs || []
    document.getElementById('d-runs').textContent = runList.length
    const tbody = document.getElementById('d-runs-table')
    tbody.innerHTML = runList.slice(0,5).map(r => `
      <tr>
        <td style="font-family:monospace;font-size:12px">${r.rid}</td>
        <td>${r.mode}</td>
        <td>${statusPill(r.status)}</td>
        <td>${r.gate ? gatePill(r.gate) : '—'}</td>
        <td>${r.total}</td>
        <td style="color:#64748b">${fmtDate(r.created_at)}</td>
      </tr>`).join('')
  } catch(e) { console.error('dashboard', e) }
}

// ── Runs ──────────────────────────────────────────────────────────────────────
async function loadRuns() {
  try {
    const data = await api('GET', '/vsp/runs?limit=50')
    const runs = data.runs || []
    document.getElementById('runs-table').innerHTML = runs.map(r => `
      <tr>
        <td style="font-family:monospace;font-size:12px">${r.rid}</td>
        <td>${r.mode}</td><td>${r.profile}</td>
        <td>${statusPill(r.status)}</td>
        <td>${r.gate ? gatePill(r.gate) : '—'}</td>
        <td>${r.total_findings}</td>
        <td>${r.tools_done}/${r.tools_total}</td>
        <td style="color:#64748b">${fmtDate(r.created_at)}</td>
      </tr>`).join('')
  } catch(e) { console.error('runs', e) }
}

async function triggerScan() {
  const mode    = document.getElementById('scanMode').value
  const profile = document.getElementById('scanProfile').value
  const src     = document.getElementById('scanSrc').value
  const msg     = document.getElementById('triggerMsg')
  if (!src) { msg.style.color='#f87171'; msg.textContent='Source path required'; return }
  try {
    msg.style.color='#94a3b8'; msg.textContent='⏳ Triggering...'
    const r = await api('POST', '/vsp/run', {mode, profile, src})
    msg.style.color='#4ade80'
    msg.textContent='✓ ' + r.rid + ' — ' + r.message
    setTimeout(loadRuns, 500)
    setTimeout(loadDashboard, 1000)
  } catch(e) {
    msg.style.color='#f87171'; msg.textContent='Error: ' + e.message
  }
}

function showTrigger() {
  document.getElementById('scanSrc').focus()
}

// ── Findings ──────────────────────────────────────────────────────────────────
async function loadFindings() {
  const sev  = document.getElementById('filterSev').value
  const tool = document.getElementById('filterTool').value
  const q    = document.getElementById('filterQ').value
  let path   = '/vsp/findings?limit=100'
  if (sev)  path += '&severity=' + sev
  if (tool) path += '&tool=' + tool
  if (q)    path += '&q=' + encodeURIComponent(q)
  try {
    const data = await api('GET', path)
    const findings = data.findings || []
    document.getElementById('findings-count').textContent = data.total + ' findings'
    document.getElementById('findings-table').innerHTML = findings.map(f => `
      <tr>
        <td>${sevPill(f.severity)}</td>
        <td style="color:#94a3b8">${f.tool}</td>
        <td style="font-family:monospace;font-size:11px;color:#60a5fa">${f.rule_id||'—'}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${esc(f.message)}">${esc(f.message)||'—'}</td>
        <td style="font-family:monospace;font-size:11px;color:#94a3b8">${esc(f.path)||'—'}</td>
        <td style="color:#64748b">${f.line||'—'}</td>
        <td style="font-size:11px;color:#818cf8">${f.cwe||'—'}</td>
      </tr>`).join('')
  } catch(e) { console.error('findings', e) }
}

// ── Policy ────────────────────────────────────────────────────────────────────
async function runEval() {
  try {
    const r = await api('POST', '/policy/evaluate', {repo: 'current'})
    const color = r.decision==='PASS' ? '#4ade80' : r.decision==='WARN' ? '#fbbf24' : '#f87171'
    document.getElementById('eval-result').innerHTML =
      `<span style="color:${color};font-size:20px;font-weight:700">${r.decision}</span>
       &nbsp; score: <b>${r.score}</b> &nbsp; posture: <b>${r.posture}</b>
       &nbsp; <span style="color:#64748b">${r.reason}</span>`
  } catch(e) {
    document.getElementById('eval-result').textContent = 'Error: ' + e.message
  }
}

async function loadRules() {
  try {
    const data = await api('GET', '/policy/rules')
    const rules = data.rules || []
    if (!rules.length) {
      document.getElementById('rules-list').innerHTML =
        '<span style="color:#64748b">No custom rules — using default policy (block critical + secrets).</span>'
      return
    }
    document.getElementById('rules-list').innerHTML = rules.map(r =>
      `<div style="padding:12px;border:1px solid #334155;border-radius:8px;margin-bottom:8px">
        <b>${r.name}</b> &nbsp;
        <span class="pill pill-pass">${r.fail_on}</span> &nbsp;
        max_high: ${r.max_high === -1 ? '∞' : r.max_high} &nbsp;
        min_score: ${r.min_score} &nbsp;
        <span style="color:#64748b">pattern: ${r.repo_pattern}</span>
       </div>`).join('')
  } catch(e) { console.error('rules', e) }
}

// ── Audit ─────────────────────────────────────────────────────────────────────
async function loadAudit() {
  try {
    const data = await api('GET', '/audit/log?limit=50')
    const entries = data.entries || []
    document.getElementById('audit-table').innerHTML = entries.map(e =>
      `<tr>
        <td style="color:#64748b">${e.seq}</td>
        <td style="color:#60a5fa">${e.action}</td>
        <td style="font-family:monospace;font-size:12px">${e.resource||'—'}</td>
        <td style="color:#64748b;font-size:12px">${e.ip||'—'}</td>
        <td style="color:#64748b">${fmtDate(e.created_at)}</td>
        <td style="font-family:monospace;font-size:10px;color:#334155">${(e.hash||'').slice(0,16)}…</td>
       </tr>`).join('')
  } catch(e) { console.error('audit', e) }
}

async function verifyAudit() {
  const el = document.getElementById('verify-result')
  el.textContent = '⏳ Verifying...'
  try {
    const r = await api('POST', '/audit/verify')
    el.innerHTML = r.ok
      ? `<span style="color:#4ade80">✓ Chain intact</span> — ${r.checked} entries verified`
      : `<span style="color:#f87171">✗ Chain broken</span> at seq ${r.broken_at_seq}: ${r.error}`
  } catch(e) { el.textContent = 'Error: ' + e.message }
}

// ── Polling ────────────────────────────────────────────────────────────────────
function startPolling() {
  setInterval(() => {
    const active = document.querySelector('.panel.active')?.id
    if (active === 'panel-dashboard') loadDashboard()
    if (active === 'panel-runs')      loadRuns()
  }, 6000)
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function statusPill(s) {
  const m = {QUEUED:'queued',RUNNING:'running',DONE:'done',FAILED:'failed',CANCELLED:'queued'}
  return `<span class="pill pill-${m[s]||'queued'}">${s}</span>`
}
function gatePill(g) {
  const m = {PASS:'pass',WARN:'warn',FAIL:'fail'}
  return `<span class="pill pill-${m[g]||'queued'}">${g}</span>`
}
function sevPill(s) {
  const m = {CRITICAL:'c-crit',HIGH:'c-high',MEDIUM:'c-med',LOW:'c-low'}
  return `<span style="font-weight:600" class="${m[s]||''}">${s}</span>`
}
function fmtDate(d) {
  if (!d) return '—'
  const dt = new Date(d)
  return dt.toLocaleDateString() + ' ' + dt.toTimeString().slice(0,8)
}
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}

// ── Boot ──────────────────────────────────────────────────────────────────────
if (TOKEN) {
  showApp()
} else {
  document.getElementById('loginScreen').style.display = 'flex'
}
</script>
</body>
</html>
VSP3STATIC_INDEX_HTML

echo ">>> go mod tidy..."
go mod tidy

echo ">>> Building all binaries..."
go build -buildvcs=false -o gateway    ./cmd/gateway/
go build -buildvcs=false -o scanner    ./cmd/scanner/
go build -buildvcs=false -o soc-shell  ./cmd/soc-shell/
echo "✓ gateway, scanner, soc-shell built"

echo ">>> Restarting services..."
pkill -f './gateway'   2>/dev/null || true
pkill -f './soc-shell' 2>/dev/null || true
sleep 1
./gateway   &
sleep 1
./soc-shell &
sleep 1

export TOKEN=$(curl -s -X POST http://localhost:8921/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@vsp.local","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo ""
echo "--- Health checks"
curl -s http://localhost:8921/health | python3 -m json.tool
curl -s http://localhost:8922/health | python3 -m json.tool

echo ""
echo "================================================================"
echo "  Phase 3 complete!"
echo ""
echo "  Gateway:   http://localhost:8921"
echo "  SOC Shell: http://localhost:8922  (open in browser!)"
echo ""
echo "  Scanner worker (requires Redis):"
echo "    docker compose -f docker/compose.dev.yml up -d"
echo "    ./scanner"
echo ""
echo "  Login: admin@vsp.local / admin123"
echo "================================================================"
