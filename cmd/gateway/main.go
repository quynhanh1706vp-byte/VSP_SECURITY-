package main

import (
	"strings"
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
	"github.com/vsp/platform/internal/pipeline"
	"github.com/vsp/platform/internal/scheduler"
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
	if err != nil { log.Fatal().Err(err).Msg("database connect failed") }
	defer db.Close()
	log.Info().Msg("database connected ✓")

	ensureDefaultTenant(ctx, db)
	db.EnsureSchedulerTables(ctx) //nolint:errcheck
	db.EnsureRemediationTable(ctx) //nolint:errcheck
	defaultTID := getDefaultTenantID(ctx, db)

	jwtSecret := viper.GetString("auth.jwt_secret")
	if jwtSecret == "" || jwtSecret == "change-me-in-production" || jwtSecret == "dev-secret-change-in-prod" {
		if viper.GetString("server.env") == "production" {
			log.Fatal().Msg("JWT secret chưa được set — từ chối khởi động ở production")
		}
		log.Warn().Msg("⚠  JWT secret đang dùng giá trị mặc định — KHÔNG dùng ở production")
	}
	jwtTTL, _ := time.ParseDuration(viper.GetString("auth.jwt_ttl"))
	if jwtTTL == 0 { jwtTTL = 24 * time.Hour }

	// SSO/OIDC config (optional — disabled by default)
	ssoConfig := auth.OIDCConfig{
		Enabled:      viper.GetBool("sso.enabled"),
		ProviderName: viper.GetString("sso.provider"),
		ClientID:     viper.GetString("sso.client_id"),
		ClientSecret: viper.GetString("sso.client_secret"),
		RedirectURL:  viper.GetString("sso.redirect_url"),
		AuthURL:      viper.GetString("sso.auth_url"),
		TokenURL:     viper.GetString("sso.token_url"),
		UserInfoURL:  viper.GetString("sso.userinfo_url"),
		DefaultRole:  viper.GetString("sso.default_role"),
	}
	viper.SetDefault("sso.enabled", false)
	viper.SetDefault("sso.provider", "google")
	viper.SetDefault("sso.default_role", "analyst")

	asynqClient := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     viper.GetString("redis.addr"),
		Password: viper.GetString("redis.password"),
	})
	defer asynqClient.Close()

	// ── All handlers ──────────────────────────────────────────────
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
	govH        := &handler.Governance{DB: db}
	exportH     := &handler.Export{DB: db}
	reportH     := &handler.Report{DB: db}
	sbomH       := &handler.SBOM{DB: db}
	slaH        := &handler.SLA{DB: db}
	sandboxH    := &handler.Sandbox{DB: db}
	importsH    := &handler.Imports{DB: db}
	remediationH   := &handler.Remediation{DB: db}
	ssoH           := handler.NewSSO(ssoConfig, authH, db)

	// Scheduler engine
	schedEngine := scheduler.New(db, func(rid, tenantID, mode, profile, src, url string) {
		runsH.EnqueueDirect(rid, tenantID, pipeline.Mode(mode), pipeline.Profile(profile), src, url)
	})
	// Wire SSE broadcast into scanner pipeline
	pipeline.SetBroadcast(handler.Hub.Broadcast)
	schedEngine.Start(ctx)
	defer schedEngine.Stop()
	schedH := &handler.Scheduler{DB: db, Engine: schedEngine}
	keyStore    := &apiKeyStore{db: db}
	rl          := vspMW.NewRateLimiter(200, time.Minute)

	// ── Router ────────────────────────────────────────────────────
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
	// SSO routes (public)
	r.Get("/auth/sso/providers", ssoH.Providers)
	r.Get("/auth/sso/login",     ssoH.Login)
	r.Get("/auth/sso/callback",  ssoH.Callback)
	r.Get("/api/v1/events", handler.SSEHandler)
	r.Get("/api/v1/ws",     handler.WSUpgradeHandler)
	r.Get("/api/docs", handler.SwaggerUI)
	r.Get("/api/docs/openapi.json", handler.SwaggerJSON)
	r.With(vspMW.StrictLimiter(10, time.Minute)).Post("/api/v1/auth/login", authH.Login)

	authMw := auth.Middleware(jwtSecret, keyStore)
	r.Group(func(r chi.Router) {
		r.Use(authMw)

		// Auth
		r.Post("/api/v1/auth/logout", authH.Logout)
		r.Post("/api/v1/auth/refresh", authH.Refresh)

		// Admin
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole("admin"))
			r.Get("/api/v1/admin/users", usersH.List)
			r.Post("/api/v1/admin/users", usersH.Create)
			r.Delete("/api/v1/admin/users/{id}", usersH.Delete)
			r.Get("/api/v1/admin/api-keys", apiKeysH.List)
			r.Post("/api/v1/admin/api-keys", apiKeysH.Create)
			r.Delete("/api/v1/admin/api-keys/{id}", apiKeysH.Delete)
		})

		// Scan
		r.Post("/api/v1/vsp/run", runsH.Trigger)
		r.Post("/api/v1/vsp/run/{rid}/cancel", runsH.Cancel)
		r.Get("/api/v1/vsp/run/latest", runsH.Latest)
		r.Get("/api/v1/vsp/run/{rid}", runsH.Get)
		r.Get("/api/v1/vsp/runs", runsH.List)
		r.Get("/api/v1/vsp/runs/index", runsH.Index)
		r.Get("/api/v1/vsp/findings", findingsH.List)
		r.Get("/api/v1/vsp/findings/summary", findingsH.Summary)

		// Gate + Policy
		r.Get("/api/v1/vsp/gate/latest", gateH.Latest)
		r.Get("/api/v1/vsp/posture/latest", gateH.PostureLatest)
		r.Post("/api/v1/policy/evaluate", gateH.Evaluate)
		r.Get("/api/v1/policy/rules", gateH.ListRules)
		r.Post("/api/v1/policy/rules", gateH.CreateRule)
		r.Delete("/api/v1/policy/rules/{id}", gateH.DeleteRule)

		// Audit
		r.Get("/api/v1/audit/log", auditH.List)
		r.Get("/api/v1/notifications", auditH.Notifications)
		r.Get("/api/v1/tenants", usersH.ListTenants)
		r.Post("/api/v1/audit/verify", auditH.Verify)

		// SIEM
		r.Get("/api/v1/siem/webhooks", siemH.List)
		r.Post("/api/v1/siem/webhooks", siemH.Create)
		r.Delete("/api/v1/siem/webhooks/{id}", siemH.Delete)
		r.Post("/api/v1/siem/webhooks/{id}/test", siemH.Test)

		// Compliance
		r.Get("/api/v1/compliance/fedramp", complianceH.FedRAMP)
		r.Get("/api/v1/compliance/cmmc",    complianceH.CMMC)
		r.Get("/api/v1/compliance/oscal/ar",   complianceH.OSCALAR)
		r.Get("/api/v1/compliance/oscal/poam", complianceH.OSCALPOAM)

		// Governance (all implemented now)
		r.Get("/api/v1/governance/risk-register",     govH.RiskRegister)
		r.Get("/api/v1/governance/ownership",          govH.Ownership)
		r.Get("/api/v1/governance/evidence",           govH.Evidence)
		r.Post("/api/v1/governance/evidence/{id}/freeze", govH.FreezeEvidence)
		r.Get("/api/v1/governance/effectiveness",      govH.Effectiveness)
		r.Get("/api/v1/governance/traceability",       govH.Traceability)
		r.Get("/api/v1/governance/raci",               govH.RACI)
		r.Get("/api/v1/governance/rule-overrides",     govH.RuleOverrides)

		// SOC (all implemented now)
		r.Get("/api/v1/soc/detection",           govH.Detection)
		r.Get("/api/v1/soc/incidents",           govH.Incidents)
		r.Get("/api/v1/soc/supply-chain",        govH.SupplyChain)
		r.Get("/api/v1/soc/release-governance",  govH.ReleaseGovernance)
		r.Get("/api/v1/soc/framework-scorecard", govH.FrameworkScorecard)
		r.Get("/api/v1/soc/roadmap",             govH.Roadmap)
		r.Get("/api/v1/soc/zero-trust",          govH.ZeroTrust)

		// Scheduler + Drift detection
		r.Get("/api/v1/schedules",           schedH.List)
		r.Post("/api/v1/schedules",          schedH.Create)
		r.Delete("/api/v1/schedules/{id}",   schedH.Delete)
		r.Patch("/api/v1/schedules/{id}/toggle", schedH.Toggle)
		r.Post("/api/v1/schedules/{id}/run", schedH.RunNow)
		r.Get("/api/v1/drift",               schedH.DriftEvents)

		// Remediation workflow
		r.Get("/api/v1/remediation",                          remediationH.List)
		r.Get("/api/v1/remediation/stats",                    remediationH.Stats)
		r.Get("/api/v1/remediation/finding/{finding_id}",     remediationH.Get)
		r.Post("/api/v1/remediation/finding/{finding_id}",    remediationH.Upsert)
		r.Post("/api/v1/remediation/{rem_id}/comments",       remediationH.AddComment)

		// SBOM
		r.Get("/api/v1/sbom/{rid}",       sbomH.Generate)
		r.Get("/api/v1/sbom/{rid}/grype", sbomH.Grype)
		// Reports
		r.Get("/api/v1/vsp/run_report_html/{rid}", reportH.HTML)
		r.Get("/api/v1/vsp/run_report_pdf/{rid}",  reportH.PDF)
		r.Get("/api/v1/vsp/executive_report_pdf/{rid}", reportH.ExecutivePDF)
		r.Get("/api/v1/vsp/executive_report_html/{rid}", reportH.ExecutiveHTML)
		// SLA + Sandbox + Imports
		r.Get("/api/v1/vsp/sla_tracker",        slaH.Tracker)
		r.Get("/api/v1/vsp/metrics_slos",       slaH.MetricsSLOs)
		r.Get("/api/v1/vsp/sandbox",            sandboxH.List)
		r.Post("/api/v1/vsp/sandbox/test-fire", sandboxH.TestFire)
		r.Delete("/api/v1/vsp/sandbox/clear",   sandboxH.Clear)
		r.Post("/api/v1/import/policies",       importsH.Policies)
		r.Post("/api/v1/import/findings",       importsH.Findings)
		r.Post("/api/v1/import/users",          importsH.Users)
		r.Post("/api/v1/vsp/rbac/session-timeout", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok","message":"session timeout updated"}`))
		})
		// Export
		r.Get("/api/v1/export/sarif/{rid}", exportH.SARIF)
		r.Get("/api/v1/export/csv/{rid}",   exportH.CSV)
		r.Get("/api/v1/export/json/{rid}",  exportH.JSON)
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
	log.Info().Str("addr", addr).Msg("VSP Gateway v0.10.0 — Enterprise Premium LIVE ✓")
	<-quit
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv.Shutdown(sctx) //nolint:errcheck
	log.Info().Msg("stopped")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","version":"0.10.0","port":%d,"tier":"enterprise"}`,
		viper.GetInt("server.gateway_port"))
}
func corsMiddleware(next http.Handler) http.Handler {
	raw := viper.GetString("server.allowed_origins")
	if raw == "" {
		raw = "http://localhost:3000,http://localhost:8922"
	}
	allowed := make(map[string]bool)
	for _, o := range strings.Split(raw, ",") {
		if o = strings.TrimSpace(o); o != "" {
			allowed[o] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
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
	if len(rawKey) < 12 { return auth.Claims{}, fmt.Errorf("key too short") }
	prefix := rawKey[:12]
	rows, err := s.db.Pool().Query(ctx,
		`SELECT id, tenant_id, hash, role, expires_at FROM api_keys WHERE prefix=$1`, prefix)
	if err != nil { return auth.Claims{}, err }
	defer rows.Close()
	for rows.Next() {
		var id, tenantID, hash, role string; var expiresAt *time.Time
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
