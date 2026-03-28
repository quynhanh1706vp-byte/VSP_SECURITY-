#!/usr/bin/env bash
# ================================================================
# VSP Go — phase4_fhj.sh  (fixed)
# F: SIEM + H: OSCAL + J: RateLimit + Prometheus
# Chay tu ~/Data/GOLANG_VSP
# ================================================================
set -e
echo ">>> Phase 4: F+H+J"
mkdir -p internal/siem internal/compliance internal/api/handler internal/api/middleware cmd/gateway

# cmd/gateway/main.go
mkdir -p "cmd/gateway"
cat > 'cmd/gateway/main.go' << 'VSP4CMD_GATEWAY_MAIN_GO'
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
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"

	"github.com/vsp/platform/internal/api/handler"
	vspMW "github.com/vsp/platform/internal/api/middleware"
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
	viper.SetDefault("redis.addr", "localhost:6379")
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

	asynqClient := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     viper.GetString("redis.addr"),
		Password: viper.GetString("redis.password"),
	})
	defer asynqClient.Close()

	authH       := &handler.Auth{DB: db, JWTSecret: jwtSecret, JWTTTL: jwtTTL, DefaultTID: defaultTID}
	usersH      := &handler.Users{DB: db}
	apiKeysH    := &handler.APIKeys{DB: db}
	runsH       := &handler.Runs{DB: db}
	runsH.SetAsynqClient(asynqClient)
	findingsH   := &handler.Findings{DB: db}
	gateH       := &handler.Gate{DB: db}
	auditH      := &handler.Audit{DB: db}
	siemH       := &handler.SIEM{DB: db}
	complianceH := &handler.Compliance{DB: db}
	keyStore    := &apiKeyStore{db: db}

	rl := vspMW.NewRateLimiter(200, time.Minute)

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(60 * time.Second))
	r.Use(corsMiddleware)
	r.Use(rl.Middleware)

	r.Handle("/metrics", handler.MetricsHandler())
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

		r.Post("/api/v1/vsp/run", runsH.Trigger)
		r.Post("/api/v1/vsp/run/{rid}/cancel", runsH.Cancel)
		r.Get("/api/v1/vsp/run/latest", runsH.Latest)
		r.Get("/api/v1/vsp/run/{rid}", runsH.Get)
		r.Get("/api/v1/vsp/runs", runsH.List)
		r.Get("/api/v1/vsp/runs/index", runsH.Index)
		r.Get("/api/v1/vsp/findings", findingsH.List)
		r.Get("/api/v1/vsp/findings/summary", findingsH.Summary)
		r.Get("/api/v1/vsp/gate/latest", gateH.Latest)
		r.Get("/api/v1/vsp/posture/latest", gateH.PostureLatest)
		r.Post("/api/v1/policy/evaluate", gateH.Evaluate)
		r.Get("/api/v1/policy/rules", gateH.ListRules)
		r.Post("/api/v1/policy/rules", gateH.CreateRule)
		r.Delete("/api/v1/policy/rules/{id}", gateH.DeleteRule)
		r.Get("/api/v1/audit/log", auditH.List)
		r.Post("/api/v1/audit/verify", auditH.Verify)
		r.Get("/api/v1/siem/webhooks", siemH.List)
		r.Post("/api/v1/siem/webhooks", siemH.Create)
		r.Delete("/api/v1/siem/webhooks/{id}", siemH.Delete)
		r.Post("/api/v1/siem/webhooks/{id}/test", siemH.Test)
		r.Get("/api/v1/compliance/oscal/ar",   complianceH.OSCALAR)
		r.Get("/api/v1/compliance/oscal/poam", complianceH.OSCALPOAM)

		for _, p := range []string{
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
	log.Info().Str("addr", addr).Msg("VSP Gateway v0.3.0 — F+H+J LIVE ✓")
	<-quit
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv.Shutdown(sctx) //nolint:errcheck
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","version":"0.3.0","port":%d}`,
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
		if r.Method == http.MethodOptions { w.WriteHeader(http.StatusNoContent); return }
		next.ServeHTTP(w, r)
	})
}

type apiKeyStore struct{ db *store.DB }
func (s *apiKeyStore) ValidateAPIKey(ctx context.Context, rawKey string) (auth.Claims, error) {
	if len(rawKey) < 12 { return auth.Claims{}, fmt.Errorf("key too short") }
	prefix := rawKey[:12]
	rows, err := s.db.Pool().Query(ctx,
		`SELECT id, tenant_id, hash, role, expires_at FROM api_keys WHERE prefix=$1`, prefix)
	if err != nil { return auth.Claims{}, err }
	defer rows.Close()
	for rows.Next() {
		var id, tenantID, hash, role string
		var expiresAt *time.Time
		rows.Scan(&id, &tenantID, &hash, &role, &expiresAt) //nolint:errcheck
		if expiresAt != nil && time.Now().After(*expiresAt) { continue }
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(rawKey)); err != nil { continue }
		go s.db.TouchAPIKey(ctx, id) //nolint:errcheck
		return auth.Claims{TenantID: tenantID, Role: role, UserID: id}, nil
	}
	return auth.Claims{}, fmt.Errorf("invalid api key")
}
func ensureDefaultTenant(ctx context.Context, db *store.DB) {
	db.Pool().Exec(ctx, `INSERT INTO tenants(slug,name,plan) VALUES('default','Default Tenant','enterprise') ON CONFLICT(slug) DO NOTHING`) //nolint:errcheck
}
func getDefaultTenantID(ctx context.Context, db *store.DB) string {
	var id string
	db.Pool().QueryRow(ctx, `SELECT id FROM tenants WHERE slug='default' LIMIT 1`).Scan(&id) //nolint:errcheck
	if id == "" { log.Fatal().Msg("default tenant not found") }
	return id
}
VSP4CMD_GATEWAY_MAIN_GO

# internal/api/handler/compliance.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/compliance.go' << 'VSP4INTERNAL_API_HANDLER_COMPLIANCE_GO'
package handler

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/compliance"
	"github.com/vsp/platform/internal/store"
)

type Compliance struct {
	DB *store.DB
}

// GET /api/v1/compliance/oscal/ar
func (h *Compliance) OSCALAR(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	runs, err := h.DB.ListRuns(r.Context(), claims.TenantID, 10, 0)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	findings, _, err := h.DB.ListFindings(r.Context(), claims.TenantID, store.FindingFilter{Limit: 500})
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	ar := compliance.BuildAR(claims.TenantID, runs, findings)

	// Support ?format=json (default) or ?format=download
	if r.URL.Query().Get("format") == "download" {
		w.Header().Set("Content-Disposition",
			"attachment; filename=oscal-ar-"+time.Now().Format("20060102")+".json")
	}
	w.Header().Set("Content-Type", "application/json")
	data, _ := compliance.ToJSON(ar)
	w.Write(data)
}

// GET /api/v1/compliance/oscal/poam
func (h *Compliance) OSCALPOAM(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	findings, _, err := h.DB.ListFindings(r.Context(), claims.TenantID,
		store.FindingFilter{Limit: 500})
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	poam := compliance.BuildPOAM(claims.TenantID, findings)

	if r.URL.Query().Get("format") == "download" {
		w.Header().Set("Content-Disposition",
			"attachment; filename=oscal-poam-"+time.Now().Format("20060102")+".json")
	}
	w.Header().Set("Content-Type", "application/json")
	data, _ := compliance.ToJSON(poam)
	w.Write(data)
}
VSP4INTERNAL_API_HANDLER_COMPLIANCE_GO

# internal/api/handler/metrics.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/metrics.go' << 'VSP4INTERNAL_API_HANDLER_METRICS_GO'
package handler

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	RunsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsp_runs_total",
		Help: "Total scan runs by mode and gate decision",
	}, []string{"mode", "gate"})

	FindingsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsp_findings_total",
		Help: "Total findings by severity and tool",
	}, []string{"severity", "tool"})

	RunDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vsp_run_duration_seconds",
		Help:    "Scan run duration in seconds",
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300},
	}, []string{"mode"})

	ActiveRuns = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vsp_active_runs",
		Help: "Currently running scans",
	})

	HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsp_http_requests_total",
		Help: "Total HTTP requests",
	}, []string{"method", "path", "status"})
)

// MetricsHandler returns the Prometheus metrics endpoint handler.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
VSP4INTERNAL_API_HANDLER_METRICS_GO

# internal/api/handler/siem.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/siem.go' << 'VSP4INTERNAL_API_HANDLER_SIEM_GO'
package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/siem"
	"github.com/vsp/platform/internal/store"
)

type SIEM struct {
	DB *store.DB
}

// GET /api/v1/siem/webhooks
func (h *SIEM) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	hooks, err := h.DB.ListSIEMWebhooks(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if hooks == nil {
		hooks = []store.SIEMWebhook{}
	}
	jsonOK(w, map[string]any{"webhooks": hooks, "total": len(hooks)})
}

// POST /api/v1/siem/webhooks
func (h *SIEM) Create(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req struct {
		Label  string `json:"label"`
		Type   string `json:"type"`
		URL    string `json:"url"`
		Secret string `json:"secret"`
		MinSev string `json:"min_sev"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Label == "" || req.URL == "" {
		jsonError(w, "label and url required", http.StatusBadRequest)
		return
	}
	if req.Type == ""   { req.Type = "generic" }
	if req.MinSev == "" { req.MinSev = "HIGH" }

	hook, err := h.DB.CreateSIEMWebhook(r.Context(), store.SIEMWebhook{
		TenantID:   claims.TenantID,
		Label:      req.Label,
		Type:       req.Type,
		URL:        req.URL,
		SecretHash: req.Secret,
		MinSev:     req.MinSev,
	})
	if err != nil {
		jsonError(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, hook)
}

// DELETE /api/v1/siem/webhooks/{id}
func (h *SIEM) Delete(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	h.DB.DeleteSIEMWebhook(r.Context(), claims.TenantID, id) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/v1/siem/webhooks/{id}/test
func (h *SIEM) Test(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")

	hooks, _ := h.DB.ListSIEMWebhooks(r.Context(), claims.TenantID)
	var target *store.SIEMWebhook
	for i := range hooks {
		if hooks[i].ID == id {
			target = &hooks[i]
			break
		}
	}
	if target == nil {
		jsonError(w, "webhook not found", http.StatusNotFound)
		return
	}

	testEvent := siem.Event{
		RID:       "RID_TEST_EVENT",
		TenantID:  claims.TenantID,
		Gate:      "WARN",
		Posture:   "B",
		Score:     75,
		Findings:  3,
		High:      3,
		Timestamp: time.Now(),
		Src:       "test",
	}
	go siem.Deliver(r.Context(), h.DB, testEvent)
	jsonOK(w, map[string]string{"status": "test event fired", "webhook": target.Label})
}
VSP4INTERNAL_API_HANDLER_SIEM_GO

# internal/api/middleware/ratelimit.go
mkdir -p "internal/api/middleware"
cat > 'internal/api/middleware/ratelimit.go' << 'VSP4INTERNAL_API_MIDDLEWARE_RATELIMIT_GO'
package middleware

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter is a simple sliding window rate limiter per IP.
type RateLimiter struct {
	mu       sync.Mutex
	windows  map[string][]time.Time
	max      int
	window   time.Duration
}

func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		windows: make(map[string][]time.Time),
		max:     max,
		window:  window,
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Prune old entries
	times := rl.windows[key]
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.max {
		rl.windows[key] = valid
		return false
	}

	rl.windows[key] = append(valid, now)
	return true
}

// Middleware returns a chi-compatible rate limiting middleware.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if !rl.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded","retry_after":60}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
VSP4INTERNAL_API_MIDDLEWARE_RATELIMIT_GO

# internal/compliance/oscal.go
mkdir -p "internal/compliance"
cat > 'internal/compliance/oscal.go' << 'VSP4INTERNAL_COMPLIANCE_OSCAL_GO'
package compliance

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/vsp/platform/internal/store"
)

// AssessmentResult is a minimal OSCAL AR structure.
type AssessmentResult struct {
	UUID       string          `json:"uuid"`
	Metadata   ARMetadata      `json:"metadata"`
	Results    []ARResult      `json:"results"`
	Generated  time.Time       `json:"generated"`
}

type ARMetadata struct {
	Title       string    `json:"title"`
	LastModified time.Time `json:"last-modified"`
	Version     string    `json:"version"`
	OSCALVersion string   `json:"oscal-version"`
}

type ARResult struct {
	UUID        string        `json:"uuid"`
	Title       string        `json:"title"`
	Start       time.Time     `json:"start"`
	End         *time.Time    `json:"end,omitempty"`
	Findings    []ARFinding   `json:"findings"`
	Observations []ARObservation `json:"observations"`
	Risks       []ARRisk      `json:"risks"`
}

type ARFinding struct {
	UUID        string `json:"uuid"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Target      ARTarget `json:"target"`
	RelatedObs  []string `json:"related-observations"`
}

type ARTarget struct {
	Type   string `json:"type"`
	ID     string `json:"target-id"`
	Status ARStatus `json:"status"`
}

type ARStatus struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type ARObservation struct {
	UUID        string    `json:"uuid"`
	Title       string    `json:"title"`
	Methods     []string  `json:"methods"`
	Collected   time.Time `json:"collected"`
	Description string    `json:"description"`
}

type ARRisk struct {
	UUID        string `json:"uuid"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Statement   string `json:"risk-statement"`
	Status      string `json:"status"`
}

// BuildAR generates an OSCAL Assessment Result from scan runs and findings.
func BuildAR(tenantID string, runs []store.Run, findings []store.Finding) *AssessmentResult {
	now := time.Now()
	ar := &AssessmentResult{
		UUID:      fmt.Sprintf("ar-%s-%d", tenantID[:8], now.Unix()),
		Generated: now,
		Metadata: ARMetadata{
			Title:        "VSP Automated Security Assessment",
			LastModified: now,
			Version:      "1.0",
			OSCALVersion: "1.1.2",
		},
	}

	// One result per run
	for _, run := range runs {
		result := ARResult{
			UUID:  fmt.Sprintf("result-%s", run.ID),
			Title: fmt.Sprintf("Scan %s — %s", run.RID, run.Mode),
			Start: run.CreatedAt,
			End:   run.FinishedAt,
		}

		// Add observation for the run
		result.Observations = append(result.Observations, ARObservation{
			UUID:        fmt.Sprintf("obs-%s", run.ID),
			Title:       "Automated Security Scan",
			Methods:     []string{"AUTOMATED"},
			Collected:   run.CreatedAt,
			Description: fmt.Sprintf("Mode: %s, Profile: %s, Gate: %s, Posture: %s, Findings: %d",
				run.Mode, run.Profile, run.Gate, run.Posture, run.TotalFindings),
		})

		// Add findings for this run
		for _, f := range findings {
			if f.RunID != run.ID { continue }
			state := "not-satisfied"
			if f.Severity == "LOW" || f.Severity == "INFO" {
				state = "not-applicable"
			}
			obsID := fmt.Sprintf("obs-f-%s", f.ID)
			result.Findings = append(result.Findings, ARFinding{
				UUID:        fmt.Sprintf("finding-%s", f.ID),
				Title:       fmt.Sprintf("[%s] %s", f.Severity, f.RuleID),
				Description: f.Message,
				Target: ARTarget{
					Type: "statement-id",
					ID:   f.Path,
					Status: ARStatus{State: state, Reason: f.CWE},
				},
				RelatedObs: []string{obsID},
			})
			// Risk for HIGH/CRITICAL
			if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
				result.Risks = append(result.Risks, ARRisk{
					UUID:        fmt.Sprintf("risk-%s", f.ID),
					Title:       fmt.Sprintf("%s: %s", f.RuleID, f.CWE),
					Description: f.Message,
					Statement:   fmt.Sprintf("File %s line %d presents %s risk", f.Path, f.LineNum, f.Severity),
					Status:      "open",
				})
			}
		}
		ar.Results = append(ar.Results, result)
	}
	return ar
}

// BuildPOAM generates an OSCAL Plan of Action & Milestones.
type POAM struct {
	UUID      string        `json:"uuid"`
	Metadata  ARMetadata    `json:"metadata"`
	Items     []POAMItem    `json:"poam-items"`
	Generated time.Time     `json:"generated"`
}

type POAMItem struct {
	UUID        string    `json:"uuid"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Origins     []string  `json:"origins"`
	Risk        string    `json:"related-risk"`
	Status      string    `json:"status"`
	DueDate     time.Time `json:"due-date"`
	Remediation string    `json:"remediation"`
}

func BuildPOAM(tenantID string, findings []store.Finding) *POAM {
	now := time.Now()
	poam := &POAM{
		UUID:      fmt.Sprintf("poam-%s-%d", tenantID[:8], now.Unix()),
		Generated: now,
		Metadata: ARMetadata{
			Title:        "VSP Plan of Action & Milestones",
			LastModified: now,
			Version:      "1.0",
			OSCALVersion: "1.1.2",
		},
	}

	for _, f := range findings {
		if f.Severity == "INFO" || f.Severity == "TRACE" { continue }
		due := now.AddDate(0, 0, dueDays(f.Severity))
		poam.Items = append(poam.Items, POAMItem{
			UUID:        fmt.Sprintf("poam-item-%s", f.ID),
			Title:       fmt.Sprintf("[%s] %s in %s", f.Severity, f.RuleID, f.Path),
			Description: f.Message,
			Origins:     []string{"VSP-Automated-Scanner", f.Tool},
			Risk:        f.CWE,
			Status:      "open",
			DueDate:     due,
			Remediation: f.FixSignal,
		})
	}
	return poam
}

func dueDays(sev string) int {
	switch sev {
	case "CRITICAL": return 3
	case "HIGH":     return 14
	case "MEDIUM":   return 30
	default:         return 90
	}
}

func ToJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
VSP4INTERNAL_COMPLIANCE_OSCAL_GO

# internal/siem/webhook.go
mkdir -p "internal/siem"
cat > 'internal/siem/webhook.go' << 'VSP4INTERNAL_SIEM_WEBHOOK_GO'
package siem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/store"
)

// WebhookType defines the payload format.
type WebhookType string

const (
	TypeGeneric  WebhookType = "generic"
	TypeSlack    WebhookType = "slack"
	TypeSplunk   WebhookType = "splunk_hec"
	TypeSentinel WebhookType = "sentinel"
	TypeDatadog  WebhookType = "datadog"
	TypeCEF      WebhookType = "cef"
)

// Event is the internal representation sent to all webhooks.
type Event struct {
	RID        string    `json:"rid"`
	TenantID   string    `json:"tenant_id"`
	Gate       string    `json:"gate"`
	Posture    string    `json:"posture"`
	Score      int       `json:"score"`
	Findings   int       `json:"total_findings"`
	Critical   int       `json:"critical"`
	High       int       `json:"high"`
	Medium     int       `json:"medium"`
	Low        int       `json:"low"`
	Timestamp  time.Time `json:"timestamp"`
	Src        string    `json:"src"`
}

// Deliver sends event to all active webhooks for a tenant.
// Errors are logged but do not fail the caller.
func Deliver(ctx context.Context, db *store.DB, event Event) {
	hooks, err := db.ListSIEMWebhooks(ctx, event.TenantID)
	if err != nil {
		log.Error().Err(err).Msg("siem: list webhooks failed")
		return
	}
	for _, hook := range hooks {
		if !hook.Active {
			continue
		}
		// Severity filter
		if !severityMeetsMin(event, hook.MinSev) {
			continue
		}
		go deliverOne(ctx, db, hook, event)
	}
}

func deliverOne(ctx context.Context, db *store.DB, hook store.SIEMWebhook, event Event) {
	payload, err := buildPayload(WebhookType(hook.Type), hook, event)
	if err != nil {
		log.Error().Err(err).Str("hook", hook.ID).Msg("siem: build payload failed")
		return
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := send(ctx, hook, payload); err != nil {
			lastErr = err
			backoff := time.Duration(attempt*attempt) * time.Second
			log.Warn().Err(err).Int("attempt", attempt).
				Str("hook", hook.Label).Msgf("siem: retry in %s", backoff)
			time.Sleep(backoff)
			continue
		}
		log.Info().Str("hook", hook.Label).Str("rid", event.RID).Msg("siem: delivered")
		// Update last_fired (best-effort)
		_ = db.TouchSIEMWebhook(context.Background(), hook.ID)
		return
	}
	log.Error().Err(lastErr).Str("hook", hook.Label).Msg("siem: delivery failed after 3 attempts")
}

func send(ctx context.Context, hook store.SIEMWebhook, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", hook.URL,
		bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VSP-Platform/0.2")

	// HMAC signature if secret configured
	if hook.SecretHash != "" {
		mac := hmac.New(sha256.New, []byte(hook.SecretHash))
		mac.Write(payload)
		req.Header.Set("X-VSP-Signature",
			fmt.Sprintf("sha256=%x", mac.Sum(nil)))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return nil
}

func buildPayload(t WebhookType, hook store.SIEMWebhook, e Event) ([]byte, error) {
	switch t {
	case TypeSlack:
		color := map[string]string{"PASS": "#36a64f", "WARN": "#ffcc00", "FAIL": "#ff0000"}[e.Gate]
		return json.Marshal(map[string]any{
			"attachments": []map[string]any{{
				"color": color,
				"title": fmt.Sprintf("VSP Scan: %s — %s", e.Gate, e.RID),
				"fields": []map[string]any{
					{"title": "Gate",     "value": e.Gate,               "short": true},
					{"title": "Posture",  "value": e.Posture,            "short": true},
					{"title": "Score",    "value": e.Score,              "short": true},
					{"title": "Critical", "value": e.Critical,           "short": true},
					{"title": "High",     "value": e.High,               "short": true},
					{"title": "Source",   "value": e.Src,                "short": false},
				},
				"footer": "VSP Security Platform",
				"ts":     e.Timestamp.Unix(),
			}},
		})
	 case TypeSplunk:
		return json.Marshal(map[string]any{
			"time":       e.Timestamp.Unix(),
			"sourcetype": "vsp:scan",
			"event":      e,
		})
	case TypeDatadog:
		return json.Marshal(map[string]any{
			"title": "VSP Scan Complete: " + e.Gate,
			"text":  fmt.Sprintf("RID: %s\nFindings: %d (C:%d H:%d M:%d L:%d)", e.RID, e.Findings, e.Critical, e.High, e.Medium, e.Low),
			"alert_type": map[string]string{"PASS": "success", "WARN": "warning", "FAIL": "error"}[e.Gate],
			"tags": []string{"source:vsp", "gate:" + e.Gate},
		})
	default: // generic
		return json.Marshal(e)
	}
}

func severityMeetsMin(e Event, minSev string) bool {
	switch minSev {
	case "CRITICAL":
		return e.Critical > 0
	case "HIGH":
		return e.Critical > 0 || e.High > 0
	case "MEDIUM":
		return e.Critical > 0 || e.High > 0 || e.Medium > 0
	default:
		return true
	}
}
VSP4INTERNAL_SIEM_WEBHOOK_GO

# internal/store/siem.go
mkdir -p "internal/store"
cat > 'internal/store/siem.go' << 'VSP4INTERNAL_STORE_SIEM_GO'
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type SIEMWebhook struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Label      string    `json:"label"`
	Type       string    `json:"type"`
	URL        string    `json:"url"`
	SecretHash string    `json:"-"`
	MinSev     string    `json:"min_sev"`
	Active     bool      `json:"active"`
	LastFired  *time.Time `json:"last_fired"`
	FireCount  int       `json:"fire_count"`
	CreatedAt  time.Time `json:"created_at"`
}

func (db *DB) ListSIEMWebhooks(ctx context.Context, tenantID string) ([]SIEMWebhook, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, tenant_id, label, type, url, secret_hash,
		        min_sev, active, last_fired, fire_count, created_at
		 FROM siem_webhooks WHERE tenant_id=$1 ORDER BY created_at DESC`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hooks []SIEMWebhook
	for rows.Next() {
		var h SIEMWebhook
		rows.Scan(&h.ID, &h.TenantID, &h.Label, &h.Type, &h.URL, &h.SecretHash,
			&h.MinSev, &h.Active, &h.LastFired, &h.FireCount, &h.CreatedAt)
		hooks = append(hooks, h)
	}
	return hooks, nil
}

func (db *DB) CreateSIEMWebhook(ctx context.Context, h SIEMWebhook) (*SIEMWebhook, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO siem_webhooks (tenant_id,label,type,url,secret_hash,min_sev)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 RETURNING id,tenant_id,label,type,url,secret_hash,min_sev,active,last_fired,fire_count,created_at`,
		h.TenantID, h.Label, h.Type, h.URL, h.SecretHash, h.MinSev)
	var out SIEMWebhook
	err := row.Scan(&out.ID, &out.TenantID, &out.Label, &out.Type, &out.URL, &out.SecretHash,
		&out.MinSev, &out.Active, &out.LastFired, &out.FireCount, &out.CreatedAt)
	if err == pgx.ErrNoRows { return nil, nil }
	if err != nil { return nil, fmt.Errorf("create siem webhook: %w", err) }
	return &out, nil
}

func (db *DB) DeleteSIEMWebhook(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM siem_webhooks WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

func (db *DB) TouchSIEMWebhook(ctx context.Context, id string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE siem_webhooks SET last_fired=NOW(), fire_count=fire_count+1 WHERE id=$1`, id)
	return err
}
VSP4INTERNAL_STORE_SIEM_GO

echo ">>> go mod tidy..."
go mod tidy
echo ">>> Building..."
go build -buildvcs=false -o gateway ./cmd/gateway/ && echo 'Build OK'
pkill -f './gateway' 2>/dev/null || true; sleep 1
./gateway &
sleep 2
export TOKEN=$(curl -s -X POST http://localhost:8921/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@vsp.local","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Token OK"
echo "--- /health"
curl -s http://localhost:8921/health | python3 -m json.tool
echo "--- OSCAL AR (first 30 lines)"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8921/api/v1/compliance/oscal/ar | python3 -m json.tool | head -30
echo "--- OSCAL POA&M (first 30 lines)"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8921/api/v1/compliance/oscal/poam | python3 -m json.tool | head -30
echo "--- Create SIEM webhook"
curl -s -X POST http://localhost:8921/api/v1/siem/webhooks \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"label":"test-slack","type":"slack","url":"https://httpbin.org/post","min_sev":"HIGH"}' \
  | python3 -m json.tool
echo "--- Prometheus metrics"
curl -s http://localhost:8921/metrics | grep vsp_ | head -10
echo ""
echo "================================================================"
echo "  Phase 4 F+H+J DONE!"
echo "  /metrics              Prometheus"
echo "  /compliance/oscal/ar  OSCAL Assessment Result"
echo "  /compliance/oscal/poam OSCAL POA&M"
echo "  /siem/webhooks        SIEM delivery"
echo "  Rate limit 200/min    active"
echo "================================================================"
