#!/usr/bin/env bash
# ================================================================
# VSP Go — phase2_abcd.sh
# Phase 2: Runs(A) + Findings(B) + Gate/Policy(C) + Audit(D)
# Chay tu ~/Data/GOLANG_VSP
# ================================================================
set -e
echo ">>> Phase 2: A+B+C+D"
mkdir -p internal/store internal/api/handler cmd/gateway

# cmd/gateway/main.go
mkdir -p "cmd/gateway"
cat > 'cmd/gateway/main.go' << 'VSP2CMD_GATEWAY_MAIN_GO'
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"

	"github.com/vsp/platform/internal/api/handler"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	viper.SetDefault("server.gateway_port", 8921)
	viper.SetDefault("auth.jwt_secret", "dev-secret-change-in-prod")
	viper.SetDefault("auth.jwt_ttl", "24h")
	viper.SetDefault("database.url", "postgres://vsp:vsp@localhost:5432/vsp_go")
	viper.SetDefault("log.level", "info")
	if err := viper.ReadInConfig(); err != nil {
		log.Warn().Err(err).Msg("no config file — using defaults")
	}

	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	ctx := context.Background()
	db, err := store.New(ctx, viper.GetString("database.url"))
	if err != nil {
		log.Fatal().Err(err).Msg("database connect failed")
	}
	defer db.Close()
	log.Info().Msg("database connected ✓")

	ensureDefaultTenant(ctx, db)
	defaultTID := getDefaultTenantID(ctx, db)

	jwtSecret := viper.GetString("auth.jwt_secret")
	jwtTTL, _ := time.ParseDuration(viper.GetString("auth.jwt_ttl"))
	if jwtTTL == 0 {
		jwtTTL = 24 * time.Hour
	}

	authH     := &handler.Auth{DB: db, JWTSecret: jwtSecret, JWTTTL: jwtTTL, DefaultTID: defaultTID}
	usersH    := &handler.Users{DB: db}
	apiKeysH  := &handler.APIKeys{DB: db}
	runsH     := &handler.Runs{DB: db}
	findingsH := &handler.Findings{DB: db}
	gateH     := &handler.Gate{DB: db}
	auditH    := &handler.Audit{DB: db}
	keyStore  := &apiKeyStore{db: db}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(corsMiddleware)

	r.Get("/health", healthHandler)
	r.Post("/api/v1/auth/login", authH.Login)

	authMw := auth.Middleware(jwtSecret, keyStore)
	r.Group(func(r chi.Router) {
		r.Use(authMw)

		r.Post("/api/v1/auth/logout", authH.Logout)
		r.Post("/api/v1/auth/refresh", authH.Refresh)

		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole("admin"))
			r.Get("/api/v1/admin/users", usersH.List)
			r.Post("/api/v1/admin/users", usersH.Create)
			r.Delete("/api/v1/admin/users/{id}", usersH.Delete)
			r.Get("/api/v1/admin/api-keys", apiKeysH.List)
			r.Post("/api/v1/admin/api-keys", apiKeysH.Create)
			r.Delete("/api/v1/admin/api-keys/{id}", apiKeysH.Delete)
		})

		// A: Runs
		r.Post("/api/v1/vsp/run", runsH.Trigger)
		r.Post("/api/v1/vsp/run/{rid}/cancel", runsH.Cancel)
		r.Get("/api/v1/vsp/run/latest", runsH.Latest)
		r.Get("/api/v1/vsp/run/{rid}", runsH.Get)
		r.Get("/api/v1/vsp/runs", runsH.List)
		r.Get("/api/v1/vsp/runs/index", runsH.Index)

		// B: Findings
		r.Get("/api/v1/vsp/findings", findingsH.List)
		r.Get("/api/v1/vsp/findings/summary", findingsH.Summary)

		// C: Gate + Policy
		r.Get("/api/v1/vsp/gate/latest", gateH.Latest)
		r.Get("/api/v1/vsp/posture/latest", gateH.PostureLatest)
		r.Post("/api/v1/policy/evaluate", gateH.Evaluate)
		r.Get("/api/v1/policy/rules", gateH.ListRules)
		r.Post("/api/v1/policy/rules", gateH.CreateRule)
		r.Delete("/api/v1/policy/rules/{id}", gateH.DeleteRule)

		// D: Audit
		r.Get("/api/v1/audit/log", auditH.List)
		r.Post("/api/v1/audit/verify", auditH.Verify)

		// Not yet implemented
		r.Get("/api/v1/siem/webhooks", handleNotImpl)
		r.Post("/api/v1/siem/webhooks", handleNotImpl)
		r.Delete("/api/v1/siem/webhooks/{id}", handleNotImpl)
		r.Post("/api/v1/siem/webhooks/{id}/test", handleNotImpl)
		for _, p := range []string{
			"/api/v1/compliance/oscal/ar", "/api/v1/compliance/oscal/poam",
			"/api/v1/governance/risk-register", "/api/v1/governance/ownership",
			"/api/v1/governance/evidence", "/api/v1/governance/effectiveness",
			"/api/v1/governance/traceability", "/api/v1/governance/raci",
			"/api/v1/governance/rule-overrides", "/api/v1/soc/detection",
			"/api/v1/soc/incidents", "/api/v1/soc/supply-chain",
			"/api/v1/soc/release-governance", "/api/v1/soc/framework-scorecard",
			"/api/v1/soc/roadmap", "/api/v1/soc/zero-trust",
		} {
			r.Get(p, handleNotImpl)
		}
		r.Post("/api/v1/governance/evidence/{id}/freeze", handleNotImpl)
	})

	addr := fmt.Sprintf(":%d", viper.GetInt("server.gateway_port"))
	srv := &http.Server{Addr: addr, Handler: r,
		ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()
	log.Info().Str("addr", addr).Msg("VSP Gateway — A+B+C+D LIVE ✓")
	<-quit
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv.Shutdown(sctx) //nolint:errcheck
	log.Info().Msg("stopped")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","version":"0.2.0","port":%d,"phase":"A+B+C+D"}`,
		viper.GetInt("server.gateway_port"))
}

func handleNotImpl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	fmt.Fprintf(w, `{"error":"not implemented","path":%q}`, r.URL.Path)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-API-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type apiKeyStore struct{ db *store.DB }

func (s *apiKeyStore) ValidateAPIKey(ctx context.Context, rawKey string) (auth.Claims, error) {
	if len(rawKey) < 12 {
		return auth.Claims{}, fmt.Errorf("key too short")
	}
	prefix := rawKey[:12]
	rows, err := s.db.Pool().Query(ctx,
		`SELECT id, tenant_id, hash, role, expires_at FROM api_keys WHERE prefix=$1`, prefix)
	if err != nil {
		return auth.Claims{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, tenantID, hash, role string
		var expiresAt *time.Time
		rows.Scan(&id, &tenantID, &hash, &role, &expiresAt) //nolint:errcheck
		if expiresAt != nil && time.Now().After(*expiresAt) {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(rawKey)); err != nil {
			continue
		}
		go s.db.TouchAPIKey(ctx, id) //nolint:errcheck
		return auth.Claims{TenantID: tenantID, Role: role, UserID: id}, nil
	}
	return auth.Claims{}, fmt.Errorf("invalid api key")
}

func ensureDefaultTenant(ctx context.Context, db *store.DB) {
	db.Pool().Exec(ctx, //nolint:errcheck
		`INSERT INTO tenants(slug,name,plan) VALUES('default','Default Tenant','enterprise')
		 ON CONFLICT(slug) DO NOTHING`)
}

func getDefaultTenantID(ctx context.Context, db *store.DB) string {
	var id string
	db.Pool().QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug='default' LIMIT 1`).Scan(&id) //nolint:errcheck
	if id == "" {
		log.Fatal().Msg("default tenant not found — run: make migrate-up")
	}
	return id
}
VSP2CMD_GATEWAY_MAIN_GO

# internal/api/handler/audit.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/audit.go' << 'VSP2INTERNAL_API_HANDLER_AUDIT_GO'
package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vsp/platform/internal/audit"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Audit struct {
	DB *store.DB
}

// GET /api/v1/audit/log
func (h *Audit) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit        := queryInt(r, "limit", 50)
	offset       := queryInt(r, "offset", 0)
	actionFilter := r.URL.Query().Get("action")

	entries, total, err := h.DB.ListAuditPaged(r.Context(),
		claims.TenantID, actionFilter, limit, offset)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	jsonOK(w, map[string]any{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// POST /api/v1/audit/verify
func (h *Audit) Verify(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	result := audit.Verify(r.Context(), &auditStoreAdapter{db: h.DB}, claims.TenantID)
	if !result.OK {
		errMsg := ""
		if result.Err != nil {
			errMsg = result.Err.Error()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":            false,
			"checked":       result.Checked,
			"broken_at_seq": result.BrokenAtSeq,
			"error":         errMsg,
		})
		return
	}
	jsonOK(w, map[string]any{
		"ok":      true,
		"checked": result.Checked,
		"message": "audit chain intact",
	})
}

// auditStoreAdapter adapts store.DB to audit.Store interface
type auditStoreAdapter struct{ db *store.DB }

func (a *auditStoreAdapter) ListAuditByTenant(ctx context.Context, tenantID string) ([]audit.Entry, error) {
	dbEntries, err := a.db.ListAuditByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	entries := make([]audit.Entry, 0, len(dbEntries))
	for _, e := range dbEntries {
		uid := ""
		if e.UserID != nil {
			uid = *e.UserID
		}
		entries = append(entries, audit.Entry{
			Seq:        e.Seq,
			TenantID:   e.TenantID,
			UserID:     uid,
			Action:     e.Action,
			Resource:   e.Resource,
			IP:         e.IP,
			PrevHash:   e.PrevHash,
			StoredHash: e.Hash,
		})
	}
	return entries, nil
}

func (a *auditStoreAdapter) WriteAudit(ctx context.Context, e audit.Entry) (int64, error) {
	uid := (*string)(nil)
	if e.UserID != "" {
		uid = &e.UserID
	}
	seq, _, err := a.db.InsertAudit(ctx, e.TenantID, uid,
		e.Action, e.Resource, e.IP, nil, e.StoredHash, e.PrevHash)
	return seq, err
}
VSP2INTERNAL_API_HANDLER_AUDIT_GO

# internal/api/handler/findings.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/findings.go' << 'VSP2INTERNAL_API_HANDLER_FINDINGS_GO'
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

	findings, total, err := h.DB.ListFindings(r.Context(), claims.TenantID, store.FindingFilter{
		Severity: q.Get("severity"),
		Tool:     q.Get("tool"),
		Search:   q.Get("q"),
		Limit:    queryInt(r, "limit", 50),
		Offset:   queryInt(r, "offset", 0),
	})
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if findings == nil { findings = []store.Finding{} }
	jsonOK(w, map[string]any{
		"findings": findings,
		"total":    total,
		"limit":    queryInt(r, "limit", 50),
		"offset":   queryInt(r, "offset", 0),
	})
}

// GET /api/v1/vsp/findings/summary
func (h *Findings) Summary(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runID := r.URL.Query().Get("run_id")

	s, err := h.DB.FindingsSummary(r.Context(), claims.TenantID, runID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, s)
}
VSP2INTERNAL_API_HANDLER_FINDINGS_GO

# internal/api/handler/gate.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/gate.go' << 'VSP2INTERNAL_API_HANDLER_GATE_GO'
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/gate"
	"github.com/vsp/platform/internal/scanner"
	"github.com/vsp/platform/internal/store"
)

type Gate struct {
	DB *store.DB
}

// GET /api/v1/vsp/gate/latest
func (h *Gate) Latest(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	run, err := h.DB.GetLatestRun(r.Context(), claims.TenantID)
	if err != nil || run == nil {
		jsonError(w, "no runs found", http.StatusNotFound)
		return
	}
	s := runSummary(run)
	jsonOK(w, map[string]any{
		"rid":     run.RID,
		"gate":    run.Gate,
		"posture": run.Posture,
		"score":   gate.Score(s),
		"status":  run.Status,
	})
}

// GET /api/v1/vsp/posture/latest
func (h *Gate) PostureLatest(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	run, err := h.DB.GetLatestRun(r.Context(), claims.TenantID)
	if err != nil || run == nil {
		jsonError(w, "no runs found", http.StatusNotFound)
		return
	}
	s := runSummary(run)
	jsonOK(w, map[string]any{
		"grade":    gate.Posture(s),
		"score":    gate.Score(s),
		"rid":      run.RID,
		"critical": s.Critical,
		"high":     s.High,
		"medium":   s.Medium,
		"low":      s.Low,
	})
}

// POST /api/v1/policy/evaluate
func (h *Gate) Evaluate(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	var req struct {
		Repo      string `json:"repo"`
		CommitSHA string `json:"commit_sha"`
		RID       string `json:"rid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}

	var run *store.Run
	var err error
	if req.RID != "" {
		run, err = h.DB.GetRunByRID(r.Context(), claims.TenantID, req.RID)
	} else {
		run, err = h.DB.GetLatestRun(r.Context(), claims.TenantID)
	}
	if err != nil || run == nil {
		jsonError(w, "no run found to evaluate", http.StatusNotFound)
		return
	}

	rules, _ := h.DB.ListPolicyRules(r.Context(), claims.TenantID)
	policyRule := gate.DefaultRule()
	if len(rules) > 0 {
		r0 := rules[0]
		policyRule = gate.PolicyRule{
			FailOn:        r0.FailOn,
			MinScore:      r0.MinScore,
			MaxHigh:       r0.MaxHigh,
			BlockSecrets:  r0.BlockSecrets,
			BlockCritical: r0.BlockCritical,
		}
	}

	s := runSummary(run)
	result := gate.Evaluate(policyRule, s)

	jsonOK(w, map[string]any{
		"decision": result.Decision,
		"reason":   result.Reason,
		"score":    result.Score,
		"posture":  result.Posture,
		"rid":      run.RID,
		"repo":     req.Repo,
		"summary":  s,
	})
}

// GET /api/v1/policy/rules
func (h *Gate) ListRules(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rules, err := h.DB.ListPolicyRules(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if rules == nil {
		rules = []store.PolicyRule{}
	}
	jsonOK(w, map[string]any{"rules": rules, "total": len(rules)})
}

// POST /api/v1/policy/rules
func (h *Gate) CreateRule(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req store.PolicyRule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	req.TenantID = claims.TenantID
	if req.Name == ""        { req.Name = "default" }
	if req.RepoPattern == "" { req.RepoPattern = "*" }
	if req.FailOn == ""      { req.FailOn = "FAIL" }
	if req.MaxHigh == 0      { req.MaxHigh = -1 }
	req.BlockCritical = true
	req.BlockSecrets  = true

	rule, err := h.DB.CreatePolicyRule(r.Context(), req)
	if err != nil {
		jsonError(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, rule)
}

// DELETE /api/v1/policy/rules/{id}
func (h *Gate) DeleteRule(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	h.DB.DeletePolicyRule(r.Context(), claims.TenantID, id) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

// runSummary converts store.Run summary JSON to scanner.Summary
func runSummary(run *store.Run) scanner.Summary {
	if run == nil {
		return scanner.Summary{}
	}
	var m map[string]int
	if err := json.Unmarshal(run.Summary, &m); err != nil {
		return scanner.Summary{}
	}
	return scanner.Summary{
		Critical: m["CRITICAL"],
		High:     m["HIGH"],
		Medium:   m["MEDIUM"],
		Low:      m["LOW"],
		Info:     m["INFO"],
	}
}
VSP2INTERNAL_API_HANDLER_GATE_GO

# internal/api/handler/runs.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/runs.go' << 'VSP2INTERNAL_API_HANDLER_RUNS_GO'
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Runs struct {
	DB *store.DB
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
VSP2INTERNAL_API_HANDLER_RUNS_GO

# internal/store/findings.go
mkdir -p "internal/store"
cat > 'internal/store/findings.go' << 'VSP2INTERNAL_STORE_FINDINGS_GO'
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Finding struct {
	ID        string          `json:"id"`
	RunID     string          `json:"run_id"`
	TenantID  string          `json:"tenant_id"`
	Tool      string          `json:"tool"`
	Severity  string          `json:"severity"`
	RuleID    string          `json:"rule_id"`
	Message   string          `json:"message"`
	Path      string          `json:"path"`
	LineNum   int             `json:"line"`
	CWE       string          `json:"cwe"`
	FixSignal string          `json:"fix_signal"`
	Raw       json.RawMessage `json:"raw,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type FindingFilter struct {
	Severity string
	Tool     string
	Search   string // message/rule/path substring
	Limit    int
	Offset   int
}

func (db *DB) InsertFindings(ctx context.Context, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	// batch insert
	for _, f := range findings {
		_, err := db.pool.Exec(ctx,
			`INSERT INTO findings
			 (run_id, tenant_id, tool, severity, rule_id, message, path, line_num, cwe, fix_signal, raw)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			f.RunID, f.TenantID, f.Tool, f.Severity, f.RuleID,
			f.Message, f.Path, f.LineNum, f.CWE, f.FixSignal, f.Raw)
		if err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}
	return nil
}

func (db *DB) ListFindings(ctx context.Context, tenantID string, f FindingFilter) ([]Finding, int64, error) {
	if f.Limit == 0 { f.Limit = 50 }

	where := []string{"tenant_id = $1"}
	args  := []any{tenantID}
	i := 2

	if f.Severity != "" {
		where = append(where, fmt.Sprintf("severity = $%d", i))
		args = append(args, strings.ToUpper(f.Severity)); i++
	}
	if f.Tool != "" {
		where = append(where, fmt.Sprintf("tool = $%d", i))
		args = append(args, f.Tool); i++
	}
	if f.Search != "" {
		where = append(where, fmt.Sprintf("(message ILIKE $%d OR rule_id ILIKE $%d OR path ILIKE $%d)", i, i, i))
		args = append(args, "%"+f.Search+"%"); i++
	}

	whereSQL := strings.Join(where, " AND ")

	var total int64
	db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM findings WHERE "+whereSQL, args...).Scan(&total)

	args = append(args, f.Limit, f.Offset)
	rows, err := db.pool.Query(ctx,
		fmt.Sprintf(`SELECT id, run_id, tenant_id, tool, severity, rule_id,
		             message, path, line_num, cwe, fix_signal, created_at
		             FROM findings WHERE %s
		             ORDER BY
		               CASE severity
		                 WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
		                 WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4
		                 ELSE 5
		               END,
		               created_at DESC
		             LIMIT $%d OFFSET $%d`, whereSQL, i, i+1),
		args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var result []Finding
	for rows.Next() {
		var fn Finding
		if err := rows.Scan(&fn.ID, &fn.RunID, &fn.TenantID, &fn.Tool,
			&fn.Severity, &fn.RuleID, &fn.Message, &fn.Path,
			&fn.LineNum, &fn.CWE, &fn.FixSignal, &fn.CreatedAt); err != nil {
			return nil, 0, err
		}
		result = append(result, fn)
	}
	return result, total, nil
}

type FindingSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

func (db *DB) FindingsSummary(ctx context.Context, tenantID, runID string) (*FindingSummary, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT severity, COUNT(*) FROM findings
		 WHERE tenant_id=$1 AND ($2='' OR run_id::text=$2)
		 GROUP BY severity`,
		tenantID, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	s := &FindingSummary{}
	for rows.Next() {
		var sev string; var cnt int
		rows.Scan(&sev, &cnt)
		switch sev {
		case "CRITICAL": s.Critical = cnt
		case "HIGH":     s.High = cnt
		case "MEDIUM":   s.Medium = cnt
		case "LOW":      s.Low = cnt
		default:         s.Info += cnt
		}
		s.Total += cnt
	}
	return s, nil
}
VSP2INTERNAL_STORE_FINDINGS_GO

# internal/store/policy.go
mkdir -p "internal/store"
cat > 'internal/store/policy.go' << 'VSP2INTERNAL_STORE_POLICY_GO'
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type PolicyRule struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Name          string    `json:"name"`
	RepoPattern   string    `json:"repo_pattern"`
	FailOn        string    `json:"fail_on"`
	MinScore      int       `json:"min_score"`
	MaxHigh       int       `json:"max_high"`
	BlockSecrets  bool      `json:"block_secrets"`
	BlockCritical bool      `json:"block_critical"`
	Active        bool      `json:"active"`
	CreatedAt     time.Time `json:"created_at"`
}

func (db *DB) ListPolicyRules(ctx context.Context, tenantID string) ([]PolicyRule, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, tenant_id, name, repo_pattern, fail_on, min_score,
		        max_high, block_secrets, block_critical, active, created_at
		 FROM policy_rules WHERE tenant_id=$1 AND active=true
		 ORDER BY created_at DESC`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []PolicyRule
	for rows.Next() {
		var r PolicyRule
		rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.RepoPattern, &r.FailOn,
			&r.MinScore, &r.MaxHigh, &r.BlockSecrets, &r.BlockCritical,
			&r.Active, &r.CreatedAt)
		rules = append(rules, r)
	}
	return rules, nil
}

func (db *DB) CreatePolicyRule(ctx context.Context, r PolicyRule) (*PolicyRule, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO policy_rules
		 (tenant_id, name, repo_pattern, fail_on, min_score, max_high, block_secrets, block_critical)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 RETURNING id, tenant_id, name, repo_pattern, fail_on, min_score,
		           max_high, block_secrets, block_critical, active, created_at`,
		r.TenantID, r.Name, r.RepoPattern, r.FailOn, r.MinScore,
		r.MaxHigh, r.BlockSecrets, r.BlockCritical)
	var out PolicyRule
	err := row.Scan(&out.ID, &out.TenantID, &out.Name, &out.RepoPattern,
		&out.FailOn, &out.MinScore, &out.MaxHigh, &out.BlockSecrets,
		&out.BlockCritical, &out.Active, &out.CreatedAt)
	if err == pgx.ErrNoRows { return nil, nil }
	if err != nil { return nil, fmt.Errorf("create policy: %w", err) }
	return &out, nil
}

func (db *DB) DeletePolicyRule(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE policy_rules SET active=false WHERE id=$1 AND tenant_id=$2`,
		id, tenantID)
	return err
}
VSP2INTERNAL_STORE_POLICY_GO

echo ">>> go mod tidy..."
go mod tidy

echo ">>> Building..."
go build -buildvcs=false -o gateway ./cmd/gateway/
echo "Build OK"

pkill -f './gateway' 2>/dev/null || pkill -f 'gateway' 2>/dev/null || true
sleep 1
./gateway &
sleep 2

export TOKEN=$(curl -s -X POST http://localhost:8921/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@vsp.local","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Token OK"

echo "--- POST /vsp/run"
RID=$(curl -s -X POST http://localhost:8921/api/v1/vsp/run \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"SAST","src":"/tmp"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['rid'])")
echo "RID: $RID"

echo "--- GET /vsp/runs"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8921/api/v1/vsp/runs | python3 -m json.tool

echo "--- GET /vsp/findings/summary"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8921/api/v1/vsp/findings/summary | python3 -m json.tool

echo "--- POST /policy/evaluate"
curl -s -X POST http://localhost:8921/api/v1/policy/evaluate \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"repo":"myapp","rid":"'$RID'"}' | python3 -m json.tool

echo "--- GET /audit/log"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8921/api/v1/audit/log | python3 -m json.tool

echo "--- POST /audit/verify"
curl -s -X POST http://localhost:8921/api/v1/audit/verify \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

echo ""
echo "================================================================"
echo "  Phase 2 A+B+C+D DONE!"
echo "  Gateway: http://localhost:8921"
echo "================================================================"
