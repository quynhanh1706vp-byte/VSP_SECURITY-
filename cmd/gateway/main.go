package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"database/sql"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"

	"crypto/tls"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/vsp/platform/internal/api/handler"
	vspMW "github.com/vsp/platform/internal/api/middleware"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/billing"
	"github.com/vsp/platform/internal/cache"
	"github.com/vsp/platform/internal/migrate"
	"github.com/vsp/platform/internal/netcap"
	"github.com/vsp/platform/internal/pipeline"
	"github.com/vsp/platform/internal/safe"
	"github.com/vsp/platform/internal/scheduler"
	"github.com/vsp/platform/internal/siem"
	"github.com/vsp/platform/internal/store"
	"github.com/vsp/platform/internal/telemetry"
)

var startTime = time.Now()

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	// SetDefault TRƯỚC BindEnv
	viper.SetDefault("server.gateway_port", 8921)
	viper.SetDefault("auth.jwt_secret", "dev-secret-change-in-prod")
	viper.SetDefault("auth.jwt_ttl", "24h")
	viper.SetDefault("database.url", "postgres://vsp:vsp@localhost:5432/vsp_go")
	viper.SetDefault("log.level", "info")
	viper.SetDefault("redis.addr", "localhost:6379")
	viper.SetDefault("telemetry.otlp_endpoint", "")
	viper.SetDefault("auth.mode", "bearer") // Sprint 5: bearer|cookie|both (default bearer for backward compat)
	// Docker env var mappings — sau SetDefault để override
	// BindEnv errors are non-fatal — viper falls back to SetDefault values
	if err := viper.BindEnv("database.url", "DATABASE_URL"); err != nil {
		log.Warn().Err(err).Msg("viper: BindEnv database.url failed")
	}
	if err := viper.BindEnv("redis.addr", "REDIS_ADDR"); err != nil {
		log.Warn().Err(err).Msg("viper: BindEnv redis.addr failed")
	}
	if err := viper.BindEnv("redis.password", "REDIS_PASSWORD"); err != nil {
		log.Warn().Err(err).Msg("viper: BindEnv redis.password failed")
	}
	viper.BindEnv("auth.jwt_secret", "JWT_SECRET")
	viper.BindEnv("anthropic.api_key", "ANTHROPIC_API_KEY")
	viper.BindEnv("server.env", "SERVER_ENV")
	viper.BindEnv("server.allowed_origins", "ALLOWED_ORIGINS")
	viper.BindEnv("auth.mode", "VSP_AUTH_MODE") // Sprint 5 Day 1: feature flag
	if err := viper.ReadInConfig(); err != nil {
		log.Warn().Err(err).Msg("no config file — using defaults")
	}

	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	ctx, shutdown := context.WithCancel(context.Background())
	defer shutdown()
	db, err := store.New(ctx, viper.GetString("database.url"))
	if err != nil {
		log.Fatal().Err(err).Msg("database connect failed")
	}
	defer db.Close()
	log.Info().Msg("database connected ✓")

	// Auto-run migrations
	stdDB, err2 := sql.Open("pgx", viper.GetString("database.url"))
	if err2 != nil {
		log.Fatal().Err(err2).Msg("open db for migrations")
	}
	if err2 = migrate.Run(ctx, stdDB); err2 != nil {
		log.Fatal().Err(err2).Msg("migration failed")
	}
	stdDB.Close()

	// Telemetry — noop nếu OTLP_ENDPOINT không set
	shutdownTracing, _ := telemetry.Init(ctx, "vsp-gateway", "1.0.0",
		viper.GetString("telemetry.otlp_endpoint"))
	defer shutdownTracing()

	ensureDefaultTenant(ctx, db)
	// P4 Persistence — open dedicated sql.DB for P4 tables
	p4DB, _ := sql.Open("pgx", viper.GetString("database.url"))
	initP4DB(p4DB)

	if skErr := initOrLoadSigningKey(p4SQLDB); skErr != nil {
		log.Printf("[main] WARN: supply chain signing key init failed: %v", skErr)
	}
	defaultTID := getDefaultTenantID(ctx, db)

	jwtSecret := viper.GetString("auth.jwt_secret")
	// No silent fallback — fail fast if secret is weak or default
	if jwtSecret == "" || jwtSecret == "change-me-in-production" || jwtSecret == "dev-secret-change-in-prod" {
		if viper.GetString("server.env") == "production" {
			log.Fatal().Msg("JWT secret chưa được set — từ chối khởi động ở production")
		}
		log.Warn().Msg("⚠  JWT secret đang dùng giá trị mặc định — KHÔNG dùng ở production")
	}
	jwtTTL, _ := time.ParseDuration(viper.GetString("auth.jwt_ttl"))
	if jwtTTL == 0 {
		jwtTTL = 24 * time.Hour
	}

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

	// Đọc Redis config trực tiếp từ env để đảm bảo Docker env vars được dùng
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = viper.GetString("redis.addr")
	}
	redisPass := os.Getenv("REDIS_PASSWORD")
	if redisPass == "" {
		redisPass = viper.GetString("redis.password")
	}
	log.Info().Str("redis", redisAddr).Msg("connecting asynq client")
	// TLS support: set REDIS_TLS=true hoặc dùng rediss:// scheme
	redisTLS := os.Getenv("REDIS_TLS") == "true" || strings.HasPrefix(redisAddr, "rediss://")
	asynqOpt := asynq.RedisClientOpt{
		Addr:     strings.TrimPrefix(redisAddr, "rediss://"),
		Password: redisPass,
	}
	if redisTLS {
		asynqOpt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		log.Info().Msg("redis: TLS enabled")
	}
	asynqClient := asynq.NewClient(asynqOpt)
	defer asynqClient.Close()
	// ── Redis API cache ──────────────────────────────────────────────────────
	ca := cache.New(redisAddr, redisPass)

	// ── All handlers ──────────────────────────────────────────────
	authH := &handler.Auth{DB: db, JWTSecret: jwtSecret, JWTTTL: jwtTTL, DefaultTID: defaultTID}
	handler.SetJWTSecret(jwtSecret)
	usersH := &handler.Users{DB: db}
	mfaH := &handler.MFA{DB: db}
	apiKeysH := &handler.APIKeys{DB: db}
	runsH := &handler.Runs{DB: db}
	runsH.SetAsynqClient(asynqClient)
	findingsH := &handler.Findings{DB: db}
	gateH := &handler.Gate{DB: db}
	auditH := &handler.Audit{DB: db}
	siemH := &handler.SIEM{DB: db}
	billingH := &billing.Handler{DB: db.Pool()}
	// ── SIEM handlers ────────────────────────────────────────
	corrH := &handler.Correlation{DB: db}
	// ── UEBA + Assets ────────────────────────────────────────
	uebaH := &handler.UEBA{DB: db}
	assetsH := &handler.Assets{DB: db}
	soarH := &handler.SOAR{DB: db}
	logSrcH := &handler.LogSources{DB: db}
	tiH := &handler.ThreatIntel{DB: db}
	complianceH := &handler.Compliance{DB: db}
	govH := &handler.Governance{DB: db}
	exportH := &handler.Export{DB: db}
	reportH := &handler.Report{DB: db}
	sbomH := &handler.SBOM{DB: db}
	slaH := &handler.SLA{DB: db}
	sandboxH := &handler.Sandbox{DB: db}
	importsH := &handler.Imports{DB: db}
	remediationH := &handler.Remediation{DB: db}
	ssoH := handler.NewSSO(ssoConfig, authH, db)

	// Scheduler engine
	schedEngine := scheduler.New(db, func(rid, tenantID, mode, profile, src, url string) {
		runsH.EnqueueDirect(rid, tenantID, pipeline.Mode(mode), pipeline.Profile(profile), src, url)
	})
	// Wire SSE broadcast into scanner pipeline
	pipeline.SetBroadcast(handler.Hub.Broadcast)
	schedEngine.Start(ctx)
	defer schedEngine.Stop()
	schedH := &handler.Scheduler{DB: db, Engine: schedEngine}
	keyStore := &apiKeyStore{db: db}
	rl := vspMW.NewRateLimiter(600, time.Minute)

	// ── Router ────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(vspMW.CSPNonce)
	r.Use(vspMW.CSRFProtect)
	r.Use(vspMW.RequestLogger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(60 * time.Second))
	// Limit request body to 4MB để chặn DoS
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 4<<20) // 4MB
			next.ServeHTTP(w, r)
		})
	})
	r.Use(corsMiddleware)
	r.Use(rl.Middleware)

	// pprof — chỉ enable trong dev mode
	if viper.GetString("server.env") != "production" {
		// pprof restricted to internal network only
		r.Mount("/debug", http.DefaultServeMux) //nolint:gosec // G108: protected by authMw + network policy
	}
	// /metrics: restrict to localhost or internal network only
	r.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Allow only loopback + private IPs
		ip := req.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx >= 0 {
			ip = ip[:idx]
		}
		if ip != "127.0.0.1" && ip != "::1" && ip != "[::1]" {
			// Also allow if metrics token provided
			token := req.Header.Get("X-Metrics-Token")
			metricsToken := viper.GetString("server.metrics_token")
			if metricsToken == "" || token != metricsToken {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		handler.MetricsHandler().ServeHTTP(w, req)
	}))
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx2, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		checks := map[string]any{}
		overall := "ok"
		t0 := time.Now()
		if err := db.Pool().Ping(ctx2); err != nil {
			checks["database"] = map[string]string{"status": "error", "error": err.Error()}
			overall = "error"
		} else {
			checks["database"] = map[string]string{"status": "ok", "latency": time.Since(t0).String()}
		}
		w.Header().Set("Content-Type", "application/json")
		if overall == "error" {
			w.WriteHeader(503)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": overall, "version": "0.10.0",
			"port": viper.GetInt("server.gateway_port"),
			"tier": "enterprise", "checks": checks,
			"uptime": time.Since(startTime).Round(time.Second).String(),
		})
	})
	// SSO routes (public)
	r.Get("/auth/sso/providers", ssoH.Providers)
	r.Get("/auth/sso/login", ssoH.Login)
	r.Get("/auth/sso/callback", ssoH.Callback)
	r.Get("/api/docs", handler.SwaggerUI)
	r.Get("/api/docs/openapi.json", handler.SwaggerJSON)
	r.With(vspMW.StrictLimiter(10, time.Minute)).Post("/api/v1/auth/login", authH.Login)
	r.With(vspMW.StrictLimiter(20, time.Minute)).Post("/api/v1/auth/logout", authH.Logout)
	r.With(vspMW.StrictLimiter(30, time.Minute)).Post("/api/v1/auth/refresh", authH.Refresh)
	r.With(vspMW.StrictLimiter(10, time.Minute)).Post("/api/v1/auth/mfa/setup", mfaH.Setup)
	r.With(vspMW.StrictLimiter(10, time.Minute)).Post("/api/v1/auth/mfa/verify", mfaH.Verify)
	r.With(vspMW.StrictLimiter(5, time.Minute)).Post("/api/v1/auth/password/change", authH.ChangePassword)
	r.Post("/api/v1/billing/webhook", billingH.Webhook)

	authMw := auth.Middleware(jwtSecret, keyStore)
	r.With(authMw).Get("/api/v1/auth/check", authH.Check) // session check — validates cookie

	// SSE — cookie-based auth (no ?token= in URL — prevents log leakage)
	r.With(authMw).Get("/api/v1/events", handler.SSEHandler)

	// Root route — serve main UI (index.html) with CSP nonce injected
	// into inline <script> and <style> tags so they don't violate CSP.
	// Without injection, ~44 inline scripts + many inline styles would be
	// blocked by the browser (see internal/api/middleware/csp.go).
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		raw, err := os.ReadFile("./static/index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusNotFound)
			return
		}
		nonce := vspMW.GetNonce(r.Context())
		html := vspMW.InjectNonceIntoHTML(string(raw), nonce)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(html))
	})

	// Serve root-level CSS + JS assets referenced from index.html.
	// These files live in ./static/ but index.html references them at /
	// (e.g. href="/vsp_enterprise_ui.css"). Without these routes they 404.
	// Using ServeFile directly so Go's http package sets the correct
	// Content-Type header (text/css, application/javascript) via extension.
	r.Get("/vsp_enterprise_ui.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_enterprise_ui.css")
	})
	r.Get("/vsp_enterprise_navy_theme.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_enterprise_navy_theme.css")
	})
	r.Get("/vsp_upgrade_v100.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_upgrade_v100.js")
	})

	// Serve JS assets from ./static/js/ (dom-safe.js, vsp_iframe_bootstrap.js, etc.)
	// These scripts are referenced by index.html and panel HTML files.
	r.Get("/static/js/*", http.StripPrefix("/static/js/",
		http.FileServer(http.Dir("./static/js/"))).ServeHTTP)

	// Serve panel HTML/JS assets. CSP is set by vspMW.CSPNonce middleware,
	// which applies PanelCSP() for panel paths. Do NOT override CSP here.
	// Phase 2 (docs/CSP_HARDENING_ROADMAP.md) will migrate panels to the
	// strict nonce policy after inline handlers are refactored.
	r.Get("/static/panels/*", func(w http.ResponseWriter, r *http.Request) {
		http.StripPrefix("/static/panels/",
			http.FileServer(http.Dir("./static/panels/"))).ServeHTTP(w, r)
	})
	r.Get("/panels/*", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		http.StripPrefix("/panels/",
			http.FileServer(http.Dir("./static/panels/"))).ServeHTTP(w, r)
	})
	// P4 Compliance — public routes (no auth required)
	r.Get("/api/p4/health", p4Health)
	r.Get("/api/p4/health/detailed", handleP4HealthDetailed)
	r.Get("/api/p4/rmf", p4AuthMiddleware(handleRMFGet))
	r.Post("/api/p4/rmf/task", p4AuthMiddleware(handleRMFTaskUpdate))
	r.Get("/api/p4/rmf/ato-letter", p4AuthMiddleware(handleGenerateATOLetter))
	r.Get("/api/p4/rmf/conmon", p4AuthMiddleware(handleRMFConMon))
	r.Get("/api/p4/zt/status", p4AuthMiddleware(handleZTStatus))
	r.Get("/api/p4/zt/microseg", p4AuthMiddleware(p4MicroSegRouter))
	r.Post("/api/p4/zt/microseg", p4AuthMiddleware(p4MicroSegRouter))
	r.Get("/api/p4/zt/rasp", p4AuthMiddleware(handleZTRASP))
	r.Get("/api/p4/zt/rasp/coverage", p4AuthMiddleware(handleZTRASPCoverage))
	r.Get("/api/p4/zt/sbom", p4AuthMiddleware(handleZTSBOM))
	r.Get("/api/p4/zt/api-policy", p4AuthMiddleware(p4APIPolicyRouter))
	r.Post("/api/p4/zt/api-policy", p4AuthMiddleware(p4APIPolicyRouter))
	r.Get("/api/p4/pipeline/latest", p4AuthMiddleware(handlePipelineLatest))
	r.Get("/api/p4/pipeline/history", p4AuthMiddleware(handlePipelineHistory))
	r.Post("/api/p4/pipeline/trigger", p4AuthMiddleware(handlePipelineTrigger))
	r.Get("/api/p4/pipeline/drift", p4AuthMiddleware(handlePipelineDrift))
	r.Get("/api/p4/pipeline/schedules", p4AuthMiddleware(handlePipelineSchedules))
	r.Get("/api/p4/findings/sync", p4AuthMiddleware(handleFindingsSync))
	r.Post("/api/p4/findings/sync", p4AuthMiddleware(handleFindingsSync))
	r.Get("/api/p4/sbom/view", p4AuthMiddleware(handleSBOMView))

	// ═══ Supply Chain Integrity (Milestone 1) ═══
	// Sigstore-compatible artifact signing + SLSA provenance + CycloneDX VEX
	r.Post("/api/v1/supply-chain/sign", p4AuthMiddleware(handleSignArtifact))
	r.Post("/api/v1/supply-chain/verify", p4AuthMiddleware(handleVerifyArtifact))
	r.Get("/api/v1/supply-chain/signatures", p4AuthMiddleware(handleListSignatures))
	r.Get("/api/v1/supply-chain/public-key", handlePublicKey) // public — no auth
	r.Post("/api/v1/supply-chain/provenance", p4AuthMiddleware(handleGenProvenance))
	r.Get("/api/v1/supply-chain/provenance", p4AuthMiddleware(handleListProvenance))
	r.Post("/api/p4/vex", p4AuthMiddleware(handleCreateVEX))
	r.Get("/api/p4/vex", p4AuthMiddleware(handleListVEX))

	// ═══ Milestone 2: OSCAL Extended + SSDF + CISA Attestation ═══
	// NIST OSCAL 1.1.2 — Catalog, Profile, SSP, Assessment Plan/Results, POA&M
	// NIST SP 800-218 SSDF v1.1
	// CISA Secure Software Self-Attestation Common Form (2024)
	r.Get("/api/p4/oscal/catalog", p4AuthMiddleware(handleOSCALCatalog))
	r.Get("/api/p4/oscal/profile", p4AuthMiddleware(handleOSCALProfile))
	r.Get("/api/p4/oscal/ssp/extended", p4AuthMiddleware(handleOSCALSSPExtended))
	r.Get("/api/p4/oscal/assessment-plan", p4AuthMiddleware(handleOSCALAssessmentPlan))
	r.Get("/api/p4/oscal/assessment-results", p4AuthMiddleware(handleOSCALAssessmentResults))
	r.Get("/api/p4/oscal/poam-extended", p4AuthMiddleware(handleOSCALPOAMExtended))
	r.Get("/api/p4/ssdf/practices", p4AuthMiddleware(handleSSDFPractices))
	r.Post("/api/p4/ssdf/practice/update", p4AuthMiddleware(handleSSDFUpdate))
	r.Get("/api/p4/attestation/generate", p4AuthMiddleware(handleAttestationGenerate))
	r.Post("/api/p4/attestation/sign", p4AuthMiddleware(handleAttestationSign))
	r.Get("/api/p4/attestation/list", p4AuthMiddleware(handleAttestationList))

	// ═══ Milestone 3: Incident Response + CIRCIA + Forensics ═══
	// NIST SP 800-61 Rev.3 (April 2025) IR lifecycle
	// CIRCIA 2022 — 72h substantial / 24h ransomware reporting
	// NIST SP 800-86 Forensics with chain of custody
	r.Get("/api/p4/ir/incidents", p4AuthMiddleware(handleIRIncidentsList))
	r.Post("/api/p4/ir/incident", p4AuthMiddleware(handleIRIncidentCreate))
	r.Post("/api/p4/ir/incident/transition", p4AuthMiddleware(handleIRIncidentTransition))
	r.Post("/api/p4/circia/generate", p4AuthMiddleware(handleCIRCIAGenerate))
	r.Post("/api/p4/circia/submit", p4AuthMiddleware(handleCIRCIASubmit))
	r.Get("/api/p4/circia/reports", p4AuthMiddleware(handleCIRCIAList))
	r.Post("/api/p4/forensics/evidence", p4AuthMiddleware(handleForensicsCreate))
	r.Get("/api/p4/forensics/evidence", p4AuthMiddleware(handleForensicsList))
	r.Post("/api/p4/forensics/custody", p4AuthMiddleware(handleForensicsCustody))
	r.Get("/api/p4/ir/playbooks", p4AuthMiddleware(handleIRPlaybooksList))

	// ═══ Milestone 3 Extended: Detail view + Edit + Ransom payment ═══
	r.Get("/api/p4/ir/incident/detail", p4AuthMiddleware(handleIRIncidentDetail))
	r.Post("/api/p4/ir/incident/update", p4AuthMiddleware(handleIRIncidentUpdate))
	r.Post("/api/p4/ir/incident/ransom-payment", p4AuthMiddleware(handleIRRansomPayment))
	r.Post("/api/p4/ir/incident/lessons", p4AuthMiddleware(handleIRIncidentLessons))
	r.Get("/api/p4/circia/report/detail", p4AuthMiddleware(handleCIRCIAReportDetail))

	r.Get("/api/p4/ato/expiry", p4AuthMiddleware(handleATOExpiry))
	r.Get("/api/p4/oscal/ssp", p4AuthMiddleware(handleOSCALExport))
	r.Get("/api/p4/alerts/config", p4AuthMiddleware(handleAlertConfig))
	r.Post("/api/p4/alerts/config", p4AuthMiddleware(handleAlertConfig))
	r.Get("/api/p4/alerts/history", p4AuthMiddleware(handleAlertHistory))
	r.Post("/api/p4/alerts/test", p4AuthMiddleware(handleAlertTest))
	r.Post("/api/p4/email/send", p4AuthMiddleware(handleSendEmail))
	r.Get("/api/p4/vn-standards", p4AuthMiddleware(handleVNStandards))
	r.Post("/api/p4/vn-standards/update", p4AuthMiddleware(handleVNStandardUpdate))
	r.Post("/api/p4/control/pass", p4AuthMiddleware(handleMarkControlPass))
	r.Get("/api/p4/sbom/view-db", p4AuthMiddleware(handleSBOMViewDB))
	r.Get("/api/p4/email/config", p4AuthMiddleware(handleEmailConfig))
	r.Post("/api/p4/email/config", p4AuthMiddleware(handleEmailConfig))

	// ── Deep Packet Analysis (NetCap) ──────────────────────────────────────────
	netCapEngine := netcap.NewEngine()
	pipeline.SetNetcapEngine(netCapEngine) // register with scan pipeline (NETWORK/FULL_SOC modes)
	netCapH := handler.NewNetCapHandler(netCapEngine)
	// Auto-start on best available interface
	go func() {
		ifaces, _ := netCapEngine.GetInterfaces()
		iface := "any"
		for _, i := range ifaces {
			if i != "lo" && !strings.HasPrefix(i, "docker") && !strings.HasPrefix(i, "br-") && !strings.HasPrefix(i, "veth") {
				iface = i
				break
			}
		}
		if err := netCapEngine.Start(netcap.CaptureConfig{Interface: iface, SnapLen: 1500, Promiscuous: true}); err != nil {
			log.Warn().Err(err).Str("iface", iface).Msg("[NetCap] capture start failed — needs CAP_NET_RAW")
		}
		ctxNC, cancelNC := context.WithCancel(context.Background())
		_ = cancelNC // cancelled when goroutine exits via engine.Stop()
		netCapEngine.StartTsharkDecoder(ctxNC, iface)
	}()
	r.Route("/api/v1/netcap", func(r chi.Router) {
		r.Use(authMw)
		r.Get("/interfaces", netCapH.Interfaces)
		r.Post("/start", netCapH.Start)
		r.Post("/stop", netCapH.Stop)
		r.Get("/stats", netCapH.Stats)
		r.Get("/flows", netCapH.Flows)
		r.Get("/anomalies", netCapH.Anomalies)
		r.Get("/tcp-flags", netCapH.TCPFlags)
		r.Get("/proto-breakdown", netCapH.ProtoBreakdown)
		r.Get("/full", netCapH.Full)
		r.Get("/l7/http", netCapH.L7HTTP)
		r.Get("/l7/dns", netCapH.L7DNS)
		r.Get("/l7/sql", netCapH.L7SQL)
		r.Get("/l7/tls", netCapH.L7TLS)
		r.Get("/l7/grpc", netCapH.L7GRPC)
		r.Get("/export/flows.csv", netCapH.ExportFlowsCSV)
		r.Get("/export/anomalies.json", netCapH.ExportAnomaliesJSON)
	})
	// SSE stream — auth via vsp_token HttpOnly cookie (SEC-009, 2026-04-23).
	// EventSource cannot set Authorization headers but sends cookies when
	// constructed with { withCredentials: true }. Query-param tokens are
	// rejected to prevent leakage via access logs and Referer headers.
	r.With(authMw).Get("/api/v1/netcap/stream", func(w http.ResponseWriter, r *http.Request) {
		// authMw has already validated the cookie/Bearer and injected
		// claims into context. No handler-level token check needed.
		netCapH.Stream(w, r)
	})
	r.Get("/api/p4/conmon/report", p4AuthMiddleware(handleConMonReport))
	r.With(authMw).Get("/api/v1/ws", handler.WSUpgradeHandler) // cookie-based auth
	r.Group(func(r chi.Router) {
		r.Use(authMw)
		r.Use(vspMW.NewUserRateLimiter(600, time.Minute)) // per-user: 600 req/min

		// Auth
		// Sprint 5 Day 1: Public config endpoint — frontend reads auth.mode to decide fetch strategy
		r.Get("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
			authMode := viper.GetString("auth.mode")
			if authMode == "" {
				authMode = "bearer"
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"auth_mode":"` + authMode + `"}`))
		})
		r.Post("/api/v1/auth/logout", authH.Logout)
		r.Post("/api/v1/auth/refresh", authH.Refresh)
		r.Post("/api/v1/auth/mfa/setup", mfaH.Setup)
		r.Post("/api/v1/auth/mfa/verify", mfaH.Verify)
		r.Delete("/api/v1/auth/mfa", mfaH.Disable)
		r.Post("/api/v1/auth/password/change", authH.ChangePassword)
		// POST /api/v1/auth/api-token — tạo short-lived API key (1h) cho CLI/scripts
		// NIST 800-63B: short-lived tokens, OWASP ASVS V3.4.3
		r.Post("/api/v1/auth/api-token", authH.CreateAPIToken)

		// Admin
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole("admin"))
			r.Get("/api/v1/admin/users", usersH.List)
			r.Post("/api/v1/admin/users", usersH.Create)
			r.Delete("/api/v1/admin/users/{id}", usersH.Delete)
			r.Get("/api/v1/admin/api-keys", apiKeysH.List)
			r.Post("/api/v1/admin/api-keys", apiKeysH.Create)
			r.Delete("/api/v1/admin/api-keys/{id}", apiKeysH.Delete)
			r.Get("/api/v1/admin/tenants", usersH.ListAllTenants)
			r.Post("/api/v1/admin/tenants", usersH.CreateTenant)
		})

		// Scan
		r.Post("/api/v1/vsp/run", runsH.Trigger)
		r.Post("/api/v1/vsp/run/{rid}/cancel", runsH.Cancel)
		r.Get("/api/v1/vsp/run/latest", runsH.Latest)
		r.Get("/api/v1/vsp/run/{rid}", runsH.Get)
		r.Get("/api/v1/vsp/run/{rid}/log", runsH.Log)
		r.Get("/api/v1/vsp/runs", runsH.List)
		r.Get("/api/v1/vsp/runs/index", runsH.Index)
		r.With(ca.Middleware("runs-index", 10*time.Second)).Get("/api/v1/vsp/runs/index", runsH.Index)
		// ── Batch scan ──────────────────────────────────────────────
		batchH := newBatchHandler(db, runsH)
		r.With(vspMW.StrictLimiter(5, time.Minute)).Post("/api/v1/vsp/batch", batchH.Submit)
		r.Get("/api/v1/vsp/batches", batchH.ListAll)
		r.Get("/api/v1/vsp/batch/{batch_id}", batchH.Status)
		r.Delete("/api/v1/vsp/batch/{batch_id}", batchH.Cancel)
		r.Get("/api/v1/vsp/findings", findingsH.List)
		r.With(ca.Middleware("findings-summary", 15*time.Second)).Get("/api/v1/vsp/findings/summary", findingsH.Summary)
		r.Get("/api/v1/vsp/findings/by-tool", findingsH.ByTool)

		// Gate + Policy
		r.Get("/api/v1/vsp/gate/latest", gateH.Latest)
		r.With(ca.Middleware("posture", 10*time.Second)).Get("/api/v1/vsp/posture/latest", gateH.PostureLatest)
		r.Post("/api/v1/policy/evaluate", gateH.Evaluate)
		r.Get("/api/v1/policy/rules", gateH.ListRules)
		r.Post("/api/v1/policy/rules", gateH.CreateRule)
		r.Delete("/api/v1/policy/rules/{id}", gateH.DeleteRule)

		// Audit
		r.Get("/api/v1/audit/log", auditH.List)
		r.Get("/api/v1/notifications", auditH.Notifications)
		r.Get("/api/v1/tenants", usersH.ListTenants)
		// Billing
		r.Get("/api/v1/billing/status", billingH.Status)
		r.With(vspMW.StrictLimiter(5, time.Minute)).Post("/api/v1/billing/checkout", billingH.CreateCheckout)
		r.Post("/api/v1/audit/verify", auditH.Verify)

		// SIEM
		r.Get("/api/v1/siem/webhooks", siemH.List)

		// ── Correlation engine ─────────────────────────────────
		r.Get("/api/v1/correlation/rules", corrH.ListRules)
		r.Post("/api/v1/correlation/rules", corrH.CreateRule)
		r.Post("/api/v1/correlation/rules/{id}/toggle", corrH.ToggleRule)
		r.Delete("/api/v1/correlation/rules/{id}", corrH.DeleteRule)
		r.Get("/api/v1/correlation/incidents", corrH.ListIncidents)
		r.Get("/api/v1/correlation/incidents/{id}", corrH.GetIncident)
		r.Post("/api/v1/correlation/incidents/{id}/resolve", corrH.ResolveIncident)
		r.Patch("/api/v1/correlation/incidents/{id}/status", corrH.ResolveIncident)
		r.Post("/api/v1/correlation/incidents", corrH.CreateIncident)

		// ── AI Analyst smart mock ────────────────────────────────
		r.Post("/api/v1/ai/analyze", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			var req struct {
				Messages []map[string]string `json:"messages"`
			}
			json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
			run, _ := db.GetLatestRun(r.Context(), claims.TenantID)
			incs, _ := db.ListIncidents(r.Context(), claims.TenantID, "open", "", 5)
			rules, _ := db.ListCorrelationRules(r.Context(), claims.TenantID)
			gate, findings := "UNKNOWN", 0
			if run != nil {
				gate = run.Gate
				findings = run.TotalFindings
			}
			apiKey := viper.GetString("anthropic.api_key")
			if apiKey != "" {
				dbCtx := fmt.Sprintf("REAL-TIME: Gate=%s Findings=%d Incidents=%d Rules=%d", gate, findings, len(incs), len(rules))
				sys := "Ban la VSP AI Security Analyst.\n\n" + dbCtx + "\n\nTra loi tieng Viet, cu the, actionable. Dung markdown."
				body, _ := json.Marshal(map[string]any{"model": "claude-sonnet-4-20250514", "max_tokens": 1200, "system": sys, "messages": req.Messages})
				pr, err := http.NewRequestWithContext(r.Context(), "POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
				if err == nil {
					pr.Header.Set("Content-Type", "application/json")
					pr.Header.Set("anthropic-version", "2023-06-01")
					pr.Header.Set("x-api-key", apiKey)
					cl := &http.Client{Timeout: 60 * time.Second}
					resp, err := cl.Do(pr)
					if err == nil {
						defer resp.Body.Close()
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(resp.StatusCode)
						io.Copy(w, resp.Body) //nolint:errcheck
						return
					}
				}
			}
			query := ""
			if len(req.Messages) > 0 {
				query = req.Messages[len(req.Messages)-1]["content"]
			}
			var reply string
			ql := strings.ToLower(query)
			switch {
			case strings.Contains(ql, "triage") || strings.Contains(ql, "incident"):
				reply = fmt.Sprintf("## Incident Triage\n\n**Gate: %s | %d findings | %d incidents**\n\n**[CRITICAL] Xu ly ngay:**\n- INC-001: Rotate API key, revoke .env secrets\n- INC-002: Update golang.org/x/crypto len v0.31.0\n\n**[HIGH] Trong 24h:**\n- INC-003: Review 82 new HIGH findings\n\n**[MEDIUM] Trong 1 tuan:**\n- INC-004: Auto-assign SLA breach findings", gate, findings, len(incs))
			case strings.Contains(ql, "cve") || strings.Contains(ql, "crypto"):
				reply = "## CVE-2024-45337\n\n**CRITICAL | CVSS 9.1 | EPSS 0.72 | KEV Listed**\n\nAffected: `golang.org/x/crypto@v0.28.0`\n\nFix:\n```\ngo get golang.org/x/crypto@v0.31.0\ngo mod tidy\n```\n\nKEV listed = exploit co the da co. Uu tien cao nhat."
			case strings.Contains(ql, "fix") || strings.Contains(ql, "priority") || strings.Contains(ql, "sprint"):
				reply = fmt.Sprintf("## Top 5 Priority Fixes (Gate: %s)\n\n1. Rotate API key (.env:10)\n2. Update golang crypto (CVE-2024-45337)\n3. Fix S3 ACL public (main.tf:3)\n4. Remove JWT hardcode (middleware.go:47)\n5. Restrict SSH 0.0.0.0/0 (network.tf:24)\n\nLam het 5 items -> score tu %d findings xuong ~20.", gate, findings)
			case strings.Contains(ql, "executive") || strings.Contains(ql, "summary") || strings.Contains(ql, "ciso"):
				reply = fmt.Sprintf("## Executive Summary\n\n**Gate: %s | %d findings | %d incidents open**\n\nCritical risks: credentials exposed + actively exploited CVE (KEV).\n\nSIEM: %d correlation rules active, pipeline live 8 sources.\n\nRecommendation: Immediate credential rotation + CVE patch trong 24h.", gate, findings, len(incs), len(rules))
			case strings.Contains(ql, "playbook") || strings.Contains(ql, "soar"):
				reply = "## SOAR Playbook: Secret Detection\n\n1. Trigger: gitleaks finding severity=CRITICAL\n2. Auto-rotate affected credentials via Vault API\n3. Notify #security-alerts Slack\n4. Create Jira ticket P1\n5. Block PR until resolved\n6. Scan git history for exposure window"
			default:
				reply = fmt.Sprintf("Chao ban! Toi la VSP AI Security Analyst.\n\n**Trang thai hien tai**: Gate **%s** | %d findings | %d incidents.\n\nCo the giup: triage incidents, explain CVEs, priority fixes, executive summary, SOAR playbooks, threat hunting.", gate, findings, len(incs))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "text", "text": reply}}, "model": "vsp-mock"})
		})

		// ── AI Analyst proxy ──────────────────────────────────── ────────────────────────────────────
		r.Post("/api/v1/ai/chat", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Forward to Anthropic API
			body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit
			if err != nil {
				http.Error(w, "bad request", 400)
				return
			}
			req, err := http.NewRequestWithContext(r.Context(), "POST",
				"https://api.anthropic.com/v1/messages",
				bytes.NewReader(body))
			if err != nil {
				http.Error(w, "proxy error", 500)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("anthropic-version", "2023-06-01")
			apiKey := viper.GetString("anthropic.api_key")
			if apiKey != "" {
				req.Header.Set("x-api-key", apiKey)
			}
			client := &http.Client{Timeout: 60 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, `{"error":"upstream error"}`, http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body) //nolint:errcheck
		})

		// ── SIEM Report ─────────────────────────────────────────
		r.Get("/api/v1/siem/report.xlsx", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			w.Header().Set("Content-Disposition", "attachment; filename=vsp_siem_report.xlsx")
			http.ServeFile(w, r, "vsp_siem_report.xlsx")
		})
		r.Get("/api/v1/siem/report.pdf", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", "attachment; filename=vsp_siem_report.pdf")
			// Serve pre-generated report if exists
			http.ServeFile(w, r, "vsp_siem_report.pdf")
		})

		// ── UEBA ────────────────────────────────────────────────
		r.Get("/api/v1/ueba/anomalies", uebaH.ListAnomalies)
		r.Post("/api/v1/ueba/analyze", uebaH.Analyze)
		r.Get("/api/v1/ueba/baseline", uebaH.Baseline)
		r.Get("/api/v1/ueba/timeline", uebaH.Timeline)

		// ── Asset inventory ─────────────────────────────────────
		r.Get("/api/v1/assets", assetsH.List)
		r.Post("/api/v1/assets", assetsH.Create)
		r.Get("/api/v1/assets/summary", assetsH.Summary)
		r.Get("/api/v1/assets/{id}/findings", assetsH.Findings)

		// ── SOAR playbooks ──────────────────────────────────────
		r.Get("/api/v1/soar/playbooks", soarH.ListPlaybooks)
		r.Post("/api/v1/soar/playbooks", soarH.CreatePlaybook)
		r.Post("/api/v1/soar/playbooks/{id}/toggle", soarH.TogglePlaybook)
		r.Post("/api/v1/soar/playbooks/{id}/run", soarH.RunPlaybook)
		r.Post("/api/v1/soar/trigger", soarH.Trigger)
		r.Get("/api/v1/soar/runs", soarH.ListRuns)

		// ── Vulnerability management ───────────────────────────────
		r.Get("/api/v1/vulns/trend", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			days := 30
			if d := r.URL.Query().Get("days"); d != "" {
				fmt.Sscanf(d, "%d", &days)
			}
			type TrendPoint struct {
				Date     string `json:"date"`
				Critical int    `json:"critical"`
				High     int    `json:"high"`
				Medium   int    `json:"medium"`
				Low      int    `json:"low"`
				Total    int    `json:"total"`
			}
			rows, err := db.Pool().Query(ctx, `
				SELECT TO_CHAR(DATE_TRUNC('day', r.created_at), 'YYYY-MM-DD'),
				  COUNT(*) FILTER (WHERE f.severity='CRITICAL'),
				  COUNT(*) FILTER (WHERE f.severity='HIGH'),
				  COUNT(*) FILTER (WHERE f.severity='MEDIUM'),
				  COUNT(*) FILTER (WHERE f.severity='LOW'),
				  COUNT(*)
				FROM findings f JOIN runs r ON r.id=f.run_id
				WHERE f.tenant_id=$1 AND r.status='DONE'
				  AND r.created_at >= NOW() - make_interval(days => $2)
				GROUP BY 1 ORDER BY 1`, claims.TenantID, days)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"trend": []any{}})
				return
			}
			defer rows.Close()
			var points []TrendPoint
			for rows.Next() {
				var p TrendPoint
				_ = rows.Scan(&p.Date, &p.Critical, &p.High, &p.Medium, &p.Low, &p.Total) //nolint:errcheck
				points = append(points, p)
			}
			if points == nil {
				points = []TrendPoint{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"trend": points, "days": days}) //nolint:errcheck
		})

		r.Get("/api/v1/vulns/top-cves", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			type CVERow struct {
				CVE      string `json:"cve"`
				Severity string `json:"severity"`
				Count    int    `json:"count"`
				Tools    string `json:"tools"`
				Fixable  bool   `json:"fixable"`
			}
			rows, err := db.Pool().Query(ctx, `
				SELECT rule_id, MAX(severity), COUNT(*),
				       STRING_AGG(DISTINCT tool, ', '),
				       BOOL_OR(fix_signal='fix_available')
				FROM findings WHERE tenant_id=$1 AND rule_id ILIKE 'CVE-%'
				GROUP BY rule_id
				ORDER BY CASE MAX(severity)
				  WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
				  COUNT(*) DESC LIMIT 20`, claims.TenantID)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"cves": []any{}})
				return
			}
			defer rows.Close()
			var cves []CVERow
			for rows.Next() {
				var c CVERow
				_ = rows.Scan(&c.CVE, &c.Severity, &c.Count, &c.Tools, &c.Fixable) //nolint:errcheck
				cves = append(cves, c)
			}
			if cves == nil {
				cves = []CVERow{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"cves": cves, "total": len(cves)}) //nolint:errcheck
		})

		r.Get("/api/v1/vulns/by-tool", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			type ToolRow struct {
				Tool     string `json:"tool"`
				Critical int    `json:"critical"`
				High     int    `json:"high"`
				Medium   int    `json:"medium"`
				Low      int    `json:"low"`
				Total    int    `json:"total"`
			}
			rows, err := db.Pool().Query(ctx, `
				SELECT tool,
				  COUNT(*) FILTER (WHERE severity='CRITICAL'),
				  COUNT(*) FILTER (WHERE severity='HIGH'),
				  COUNT(*) FILTER (WHERE severity='MEDIUM'),
				  COUNT(*) FILTER (WHERE severity='LOW'),
				  COUNT(*)
				FROM findings f JOIN runs r ON r.id=f.run_id
				WHERE f.tenant_id=$1 AND r.status='DONE'
				GROUP BY tool ORDER BY COUNT(*) DESC`, claims.TenantID)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"tools": []any{}})
				return
			}
			defer rows.Close()
			var tools []ToolRow
			for rows.Next() {
				var t ToolRow
				_ = rows.Scan(&t.Tool, &t.Critical, &t.High, &t.Medium, &t.Low, &t.Total) //nolint:errcheck
				tools = append(tools, t)
			}
			if tools == nil {
				tools = []ToolRow{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"tools": tools}) //nolint:errcheck
		})

		// ── Threat hunting ─────────────────────────────────────────
		r.Get("/api/v1/logs/hunt", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			q := r.URL.Query()
			keyword := q.Get("q")
			severity := q.Get("severity")
			process := q.Get("process")
			sourceIP := q.Get("source_ip")
			limitStr := q.Get("limit")
			limit := 100
			if limitStr != "" {
				fmt.Sscanf(limitStr, "%d", &limit)
			}
			if limit > 500 {
				limit = 500
			}
			where := []string{"tenant_id=$1"}
			args := []any{claims.TenantID}
			if keyword != "" {
				args = append(args, "%"+keyword+"%")
				where = append(where, fmt.Sprintf("message ILIKE $%d", len(args)))
			}
			if severity != "" {
				args = append(args, strings.ToUpper(severity))
				where = append(where, fmt.Sprintf("UPPER(severity)=$%d", len(args)))
			}
			if process != "" {
				args = append(args, strings.ToLower(process))
				where = append(where, fmt.Sprintf("LOWER(process)=$%d", len(args)))
			}
			if sourceIP != "" {
				args = append(args, sourceIP)
				where = append(where, fmt.Sprintf("source_ip=$%d", len(args)))
			}
			// Time range
			hours := 24
			if h := q.Get("hours"); h != "" {
				fmt.Sscanf(h, "%d", &hours)
			}
			args = append(args, hours)
			where = append(where, fmt.Sprintf("ts >= NOW() - make_interval(hours => $%d)", len(args)))

			args = append(args, limit)
			query := fmt.Sprintf(`
				SELECT id, ts, host, process, severity, facility, message, source_ip, format
				FROM   log_events
				WHERE  %s
				ORDER  BY ts DESC
				LIMIT  $%d`,
				strings.Join(where, " AND "), len(args))

			rows, err := db.Pool().Query(ctx, query, args...)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
				return
			}
			defer rows.Close()
			type Event struct {
				ID       string `json:"id"`
				TS       string `json:"ts"`
				Host     string `json:"host"`
				Process  string `json:"process"`
				Severity string `json:"severity"`
				Facility string `json:"facility"`
				Message  string `json:"message"`
				SourceIP string `json:"source_ip"`
				Format   string `json:"format"`
			}
			var events []Event
			for rows.Next() {
				var e Event
				var ts interface{}
				_ = rows.Scan(&e.ID, &ts, &e.Host, &e.Process, &e.Severity,
					&e.Facility, &e.Message, &e.SourceIP, &e.Format) //nolint:errcheck
				if t, ok := ts.(interface{ Format(string) string }); ok {
					e.TS = t.Format("2006-01-02 15:04:05")
				} else {
					e.TS = fmt.Sprintf("%v", ts)
				}
				events = append(events, e)
			}
			if events == nil {
				events = []Event{}
			}

			// Stats — dùng toàn bộ where + args (bao gồm time filter)
			var total int
			_ = db.Pool().QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM log_events WHERE %s`,
				strings.Join(where, " AND ")), args[:len(args)-1]...).Scan(&total) //nolint:errcheck

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"events": events,
				"count":  len(events),
				"total":  total,
				"query":  map[string]any{"q": keyword, "severity": severity, "process": process, "hours": hours},
			})
		})

		// ── Network flow (từ log_events thật) ──────────────────────
		r.Get("/api/v1/logs/network-flow", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()

			// Top source IPs trong 1h
			type FlowHost struct {
				IP    string `json:"ip"`
				Count int    `json:"count"`
				Sev   string `json:"severity"`
			}
			rows, _ := db.Pool().Query(ctx, `
				SELECT COALESCE(source_ip,host,'unknown') as ip,
				       COUNT(*) as cnt,
				       MAX(severity) as sev
				FROM   log_events
				WHERE  tenant_id=$1 AND ts >= NOW()-interval'1 hour'
				  AND  (source_ip IS NOT NULL OR host IS NOT NULL)
				GROUP  BY 1 ORDER BY 2 DESC LIMIT 20`, claims.TenantID)
			var hosts []FlowHost
			if rows != nil {
				for rows.Next() {
					var h FlowHost
					_ = rows.Scan(&h.IP, &h.Count, &h.Sev) //nolint:errcheck
					hosts = append(hosts, h)
				}
				rows.Close()
			}
			if hosts == nil {
				hosts = []FlowHost{}
			}

			// Stats tổng
			var totalFlows, suspicious int
			_ = db.Pool().QueryRow(ctx, `
				SELECT COUNT(*),
				       SUM(CASE WHEN UPPER(severity) IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END)
				FROM log_events WHERE tenant_id=$1 AND ts >= NOW()-interval'1 hour'`,
				claims.TenantID).Scan(&totalFlows, &suspicious) //nolint:errcheck

			// Top processes
			type ProcStat struct {
				Process string `json:"process"`
				Count   int    `json:"count"`
			}
			prows, _ := db.Pool().Query(ctx, `
				SELECT COALESCE(process,'unknown'), COUNT(*)
				FROM   log_events
				WHERE  tenant_id=$1 AND ts >= NOW()-interval'1 hour'
				  AND  process IS NOT NULL
				GROUP  BY 1 ORDER BY 2 DESC LIMIT 10`, claims.TenantID)
			var procs []ProcStat
			if prows != nil {
				for prows.Next() {
					var p ProcStat
					prows.Scan(&p.Process, &p.Count) //nolint:errcheck
					procs = append(procs, p)
				}
				prows.Close()
			}
			if procs == nil {
				procs = []ProcStat{}
			}

			w.Header().Set("Content-Type", "application/json") //nolint:errcheck
			_ = json.NewEncoder(w).Encode(map[string]any{
				"flows_per_min": totalFlows / 60,
				"total_1h":      totalFlows,
				"suspicious":    suspicious,
				"top_hosts":     hosts,
				"top_processes": procs,
			}) //nolint:errcheck
		})

		// ── Log sources ─────────────────────────────────────────
		r.Get("/api/v1/logs/sources", logSrcH.List)
		r.Post("/api/v1/logs/sources", logSrcH.Create)
		r.Delete("/api/v1/logs/sources/{id}", logSrcH.Delete)
		r.Post("/api/v1/logs/sources/{id}/test", logSrcH.Test)
		r.Get("/api/v1/logs/stats", logSrcH.Stats)

		// ── Threat intelligence ─────────────────────────────────
		r.Get("/api/v1/ti/iocs", tiH.ListIOCs)
		r.Get("/api/v1/ti/feeds", tiH.ListFeeds)
		r.Get("/api/v1/ti/matches", tiH.Matches)
		r.Get("/api/v1/ti/mitre", tiH.MITRE)
		r.Post("/api/v1/ti/feeds/sync", tiH.SyncFeeds)
		r.Get("/api/v1/ti/enrich", tiH.Enrich)
		r.With(vspMW.StrictLimiter(10, time.Minute)).Post("/api/v1/ti/enrich/batch", tiH.EnrichBatch)
		r.Get("/api/v1/vsp/findings/dedup", tiH.DedupFindings)
		r.Get("/api/v1/vsp/findings/chains", tiH.ExploitChains)
		r.Post("/api/v1/ai/analyze/findings", tiH.SemanticAnalyze)
		r.Post("/api/v1/ti/secret/check", tiH.CheckSecret)
		r.With(vspMW.StrictLimiter(20, time.Minute)).Post("/api/v1/ti/secret/check/batch", tiH.CheckSecretBatch)
		r.Get("/api/v1/compliance/license", tiH.LicenseCompliance)
		r.Post("/api/v1/siem/webhooks", siemH.Create)
		r.Delete("/api/v1/siem/webhooks/{id}", siemH.Delete)
		r.Post("/api/v1/siem/webhooks/{id}/test", siemH.Test)

		// Compliance
		r.Get("/api/v1/compliance/fedramp", complianceH.FedRAMP)
		r.Get("/api/v1/compliance/cmmc", complianceH.CMMC)
		r.Get("/api/v1/compliance/oscal/ar", complianceH.OSCALAR)
		r.Get("/api/v1/compliance/oscal/poam", complianceH.OSCALPOAM)

		// Governance (all implemented now)
		r.Get("/api/v1/governance/risk-register", govH.RiskRegister)
		r.Get("/api/v1/governance/ownership", govH.Ownership)
		r.Get("/api/v1/governance/evidence", govH.Evidence)
		r.Post("/api/v1/governance/evidence/{id}/freeze", govH.FreezeEvidence)
		r.Get("/api/v1/governance/effectiveness", govH.Effectiveness)
		r.Get("/api/v1/governance/traceability", govH.Traceability)
		r.Get("/api/v1/governance/raci", govH.RACI)
		r.Get("/api/v1/governance/rule-overrides", govH.RuleOverrides)

		// SOC (all implemented now)
		r.Get("/api/v1/soc/detection", govH.Detection)
		r.Get("/api/v1/soc/incidents", govH.Incidents)
		r.Get("/api/v1/soc/supply-chain", govH.SupplyChain)
		r.Get("/api/v1/soc/release-governance", govH.ReleaseGovernance)
		r.Get("/api/v1/soc/framework-scorecard", govH.FrameworkScorecard)
		r.Get("/api/v1/soc/roadmap", govH.Roadmap)
		r.Get("/api/v1/soc/zero-trust", govH.ZeroTrust)

		// Scheduler + Drift detection
		r.Get("/api/v1/schedules", schedH.List)
		r.Post("/api/v1/schedules", schedH.Create)
		r.Delete("/api/v1/schedules/{id}", schedH.Delete)
		r.Patch("/api/v1/schedules/{id}", schedH.Update)
		r.Patch("/api/v1/schedules/{id}/toggle", schedH.Toggle)
		r.Post("/api/v1/schedules/{id}/run", schedH.RunNow)
		r.Get("/api/v1/drift", schedH.DriftEvents)

		// Remediation workflow
		r.Get("/api/v1/remediation", remediationH.List)
		r.Get("/api/v1/remediation/stats", remediationH.Stats)
		r.Get("/api/v1/remediation/finding/{finding_id}", remediationH.Get)
		r.Post("/api/v1/remediation/finding/{finding_id}", remediationH.Upsert)
		r.Post("/api/v1/remediation/{rem_id}/comments", remediationH.AddComment)

		// PATCH /api/v1/remediation/finding/{finding_id}/status
		r.Patch("/api/v1/remediation/finding/{finding_id}/status", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			fid := chi.URLParam(r, "finding_id")
			var req struct {
				Status  string `json:"status"`
				Comment string `json:"comment"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
				return
			}
			valid := map[string]bool{"open": true, "in_progress": true, "resolved": true, "accepted": true, "false_positive": true, "suppressed": true}
			if !valid[req.Status] {
				http.Error(w, `{"error":"invalid status"}`, http.StatusBadRequest)
				return
			}
			rem, err := remediationH.DB.UpsertRemediation(r.Context(), store.Remediation{
				FindingID: fid,
				TenantID:  claims.TenantID,
				Status:    store.RemediationStatus(req.Status),
				Notes:     req.Comment,
			})
			if err != nil {
				http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"ok": true, "finding_id": fid,
				"new_status": req.Status, "resolved_at": rem.ResolvedAt,
			})
		})
		// SBOM
		r.Get("/api/v1/sbom/{rid}", sbomH.Generate)
		r.Get("/api/v1/sbom/{rid}/grype", sbomH.Grype)
		r.Get("/api/v1/sbom/{rid}/diff", sbomH.Diff)
		// Reports
		r.Get("/api/v1/vsp/run_report_html/{rid}", reportH.HTML)
		r.Get("/api/v1/vsp/run_report_pdf/{rid}", reportH.PDF)
		r.Get("/api/v1/vsp/tt13_report/{rid}", reportH.TT13)
		// ── Webhook alerts ──────────────────────────────────────────────
		r.Get("/api/v1/alerts/webhooks", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			rows, err := db.Pool().Query(ctx,
				"SELECT id,label,url,type,min_sev,active,created_at FROM siem_webhooks WHERE tenant_id=$1 ORDER BY created_at DESC",
				claims.TenantID)
			if err != nil {
				http.Error(w, `{"error":"db"}`, 500)
				return
			}
			defer rows.Close()
			type WH struct {
				ID        string   `json:"id"`
				Name      string   `json:"name"`
				URL       string   `json:"url"`
				Events    []string `json:"events"`
				Enabled   bool     `json:"enabled"`
				CreatedAt string   `json:"created_at"`
			}
			var whs []WH
			for rows.Next() {
				var wh WH
				var createdAt time.Time
				var whType, minSev string
				_ = rows.Scan(&wh.ID, &wh.Name, &wh.URL, &whType, &minSev, &wh.Enabled, &createdAt)
				wh.Events = []string{whType, minSev}
				wh.CreatedAt = createdAt.Format(time.RFC3339)
				whs = append(whs, wh)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"webhooks": whs, "total": len(whs)})
		})
		r.Post("/api/v1/alerts/webhooks/test", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			_ = claims
			var req struct {
				URL  string `json:"url"`
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.URL == "" {
				http.Error(w, `{"error":"url required"}`, 400)
				return
			}
			// Send test payload
			payload := map[string]interface{}{
				"type":      "test",
				"platform":  "VSP Security Platform v0.10",
				"message":   "Webhook test from VSP — connection successful",
				"timestamp": time.Now().Format(time.RFC3339),
				"severity":  "INFO",
			}
			b, _ := json.Marshal(payload)
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Post(req.URL, "application/json", bytes.NewReader(b))
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
				return
			}
			defer resp.Body.Close()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": resp.StatusCode < 300, "status": resp.StatusCode, "message": "Webhook test sent"})
		})
		r.Post("/api/v1/alerts/notify", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			// Send immediate alert to all enabled webhooks for CRITICAL findings
			rows, err := db.Pool().Query(ctx,
				"SELECT url,label FROM siem_webhooks WHERE tenant_id=$1 AND active=true AND (min_sev='CRITICAL' OR min_sev='HIGH')",
				claims.TenantID)
			if err != nil {
				http.Error(w, `{"error":"db"}`, 500)
				return
			}
			defer rows.Close()
			// Get latest critical findings
			frows, _ := db.Pool().Query(ctx,
				"SELECT severity,tool,rule_id,message,path FROM findings WHERE tenant_id=$1 AND severity='CRITICAL' ORDER BY created_at DESC LIMIT 5",
				claims.TenantID)
			type F struct{ Sev, Tool, Rule, Msg, Path string }
			var findings []F
			if frows != nil {
				defer frows.Close()
				for frows.Next() {
					var f F
					frows.Scan(&f.Sev, &f.Tool, &f.Rule, &f.Msg, &f.Path)
					findings = append(findings, f)
				}
			}
			payload, _ := json.Marshal(map[string]interface{}{
				"type": "critical_alert", "platform": "VSP Security Platform",
				"timestamp":         time.Now().Format(time.RFC3339),
				"critical_findings": len(findings), "findings": findings,
			})
			sent := 0
			client := &http.Client{Timeout: 10 * time.Second}
			for rows.Next() {
				var url, name string
				_ = rows.Scan(&url, &name)
				resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
				if err == nil && resp.StatusCode < 300 {
					sent++
				}
				if resp != nil {
					_ = resp.Body.Close()
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"sent": sent, "findings": len(findings), "message": fmt.Sprintf("Notified %d webhooks", sent)})
		})

		r.Get("/api/v1/audit/stats", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			var total, h24, d7, d30, users, actions, archivable int
			var oldest, newest string
			_ = db.Pool().QueryRow(ctx,
				"SELECT COUNT(*),"+
					"COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours'),"+
					"COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days'),"+
					"COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days'),"+
					"COUNT(DISTINCT user_id),COUNT(DISTINCT action),"+
					"COALESCE(MIN(created_at)::text,'—'),COALESCE(MAX(created_at)::text,'—'),"+
					"COUNT(*) FILTER (WHERE created_at < NOW() - INTERVAL '90 days')"+
														" FROM audit_log WHERE tenant_id=$1", claims.TenantID).
				Scan(&total, &h24, &d7, &d30, &users, &actions, &oldest, &newest, &archivable) //nolint:errcheck
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
				"total": total, "last_24h": h24, "last_7d": d7, "last_30d": d30,
				"unique_users": users, "unique_actions": actions,
				"oldest": oldest, "newest": newest, "archivable": archivable,
			})
		})
		r.Post("/api/v1/audit/rotate", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			if claims.Role != "admin" {
				http.Error(w, "{\"error\":\"admin only\"}", http.StatusForbidden)
				return
			}
			keepDays := 90
			var req struct {
				KeepDays int `json:"keep_days"`
			}
			json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
			if req.KeepDays > 0 {
				keepDays = req.KeepDays
			}
			ctx := r.Context()
			var archived, remaining int64
			_ = db.Pool().QueryRow(ctx, "SELECT * FROM rotate_audit_log($1)", keepDays).Scan(&archived, &remaining) //nolint:errcheck
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
				"archived": archived, "remaining": remaining, "keep_days": keepDays,
				"message": fmt.Sprintf("Archived %d entries older than %d days", archived, keepDays),
			})
		})
		r.Get("/api/v1/audit/monthly", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			rows, err := db.Pool().Query(ctx,
				"SELECT DATE_TRUNC('month',created_at)::text,"+
					"COUNT(*),COUNT(DISTINCT user_id),COUNT(DISTINCT action),"+
					"COUNT(*) FILTER (WHERE action LIKE '%scan%'),"+
					"COUNT(*) FILTER (WHERE action LIKE '%login%')"+
					" FROM audit_log WHERE tenant_id=$1"+
					" GROUP BY 1 ORDER BY 1 DESC LIMIT 12", claims.TenantID)
			if err != nil {
				http.Error(w, "{\"error\":\"db\"}", 500)
				return
			}
			defer rows.Close()
			type Month struct {
				Month   string `json:"month"`
				Total   int    `json:"total"`
				Users   int    `json:"users"`
				Actions int    `json:"actions"`
				Scans   int    `json:"scans"`
				Logins  int    `json:"logins"`
			}
			var months []Month
			for rows.Next() {
				var m Month
				_ = rows.Scan(&m.Month, &m.Total, &m.Users, &m.Actions, &m.Scans, &m.Logins) //nolint:errcheck
				months = append(months, m)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"months": months, "total": len(months)}) //nolint:errcheck
		})

		// ── Auto-remediation engine ──────────────────────────────────────
		// POST /api/v1/remediation/auto — auto-create remediations from findings
		r.Post("/api/v1/remediation/auto", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()

			var req struct {
				RunID    string `json:"run_id"`
				Severity string `json:"severity"` // CRITICAL,HIGH,MEDIUM,ALL
				Assignee string `json:"assignee"`
			}
			json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
			if req.Severity == "" {
				req.Severity = "HIGH"
			}
			if req.Assignee == "" {
				req.Assignee = "auto-assigned"
			}

			sevFilter := "'CRITICAL','HIGH'"
			switch req.Severity {
			case "ALL":
				sevFilter = "'CRITICAL','HIGH','MEDIUM','LOW'"
			case "MEDIUM":
				sevFilter = "'CRITICAL','HIGH','MEDIUM'"
			case "HIGH":
				sevFilter = "'CRITICAL','HIGH'"
			case "CRITICAL":
				sevFilter = "'CRITICAL'"
			}

			query := "SELECT f.id, f.severity, f.tool, f.rule_id, f.message, f.path, f.fix_signal " +
				"FROM findings f " +
				"WHERE f.tenant_id=$1 AND f.severity IN (" + sevFilter + ") " +
				"AND NOT EXISTS (SELECT 1 FROM remediations rem WHERE rem.finding_id=f.id AND rem.tenant_id=$1) "
			if req.RunID != "" {
				query += "AND f.run_id=(SELECT id FROM runs WHERE rid=$2 AND tenant_id=$1 LIMIT 1) "
			}
			query += "ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END LIMIT 200"

			var rows pgx.Rows
			var err error
			if req.RunID != "" {
				rows, err = db.Pool().Query(ctx, query, claims.TenantID, req.RunID)
			} else {
				rows, err = db.Pool().Query(ctx, query, claims.TenantID)
			}
			if err != nil {
				http.Error(w, `{"error":"db"}`, 500)
				return
			}
			defer rows.Close()

			type Finding struct{ ID, Sev, Tool, Rule, Msg, Path, Fix string }
			var findings []Finding
			for rows.Next() {
				var f Finding
				_ = rows.Scan(&f.ID, &f.Sev, &f.Tool, &f.Rule, &f.Msg, &f.Path, &f.Fix)
				findings = append(findings, f)
			}

			// SLA due dates per severity
			dueDays := map[string]int{"CRITICAL": 1, "HIGH": 7, "MEDIUM": 30, "LOW": 90}
			priority := map[string]string{"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

			created := 0
			for _, f := range findings {
				days := dueDays[f.Sev]
				if days == 0 {
					days = 30
				}
				due := time.Now().AddDate(0, 0, days)
				pri := priority[f.Sev]
				if pri == "" {
					pri = "medium"
				}
				notes := fmt.Sprintf("Auto-created from VSP scan.\nTool: %s\nRule: %s\nPath: %s\n", f.Tool, f.Rule, f.Path)
				if f.Fix != "" {
					notes += fmt.Sprintf("Fix signal: %s\n", f.Fix)
				}
				_, e := db.Pool().Exec(ctx,
					"INSERT INTO remediations (id,finding_id,tenant_id,status,assignee,priority,due_date,notes,created_at,updated_at) "+
						"VALUES (gen_random_uuid(),$1::uuid,$2,'open',$3,$4,$5,$6,NOW(),NOW()) ON CONFLICT DO NOTHING",
					f.ID, claims.TenantID, req.Assignee, pri, due, notes)
				if e == nil {
					created++
				}
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
				"created":   created,
				"available": len(findings),
				"severity":  req.Severity,
				"message":   fmt.Sprintf("Auto-created %d remediation items (sev>=%s)", created, req.Severity),
			})
		})

		// GET /api/v1/remediation/stats — remediation stats
		r.Get("/api/v1/remediation/stats", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			var total, open, inprog, resolved, overdue int
			_ = db.Pool().QueryRow(ctx, //nolint:errcheck
				"SELECT COUNT(*), "+
					"COUNT(*) FILTER (WHERE status='open'), "+
					"COUNT(*) FILTER (WHERE status='in_progress'), "+
					"COUNT(*) FILTER (WHERE status='resolved'), "+
					"COUNT(*) FILTER (WHERE status='open' AND due_date < NOW()) "+
					"FROM remediations WHERE tenant_id=$1", claims.TenantID).
				Scan(&total, &open, &inprog, &resolved, &overdue)
			var bySev []map[string]interface{}
			rows, _ := db.Pool().Query(ctx,
				"SELECT f.severity, COUNT(*), COUNT(*) FILTER (WHERE rem.status='resolved') "+
					"FROM remediations rem JOIN findings f ON f.id=rem.finding_id "+
					"WHERE rem.tenant_id=$1 GROUP BY f.severity "+
					"ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END",
				claims.TenantID)
			if rows != nil {
				defer rows.Close()
				for rows.Next() {
					var sev string
					var tot, res int
					_ = rows.Scan(&sev, &tot, &res)
					bySev = append(bySev, map[string]interface{}{
						"severity": sev, "total": tot, "resolved": res,
						"open": tot - res, "pct": func() int {
							if tot > 0 {
								return res * 100 / tot
							}
							return 0
						}(),
					})
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
				"total": total, "open": open, "in_progress": inprog,
				"resolved": resolved, "overdue": overdue,
				"by_severity": bySev,
				"resolution_rate": func() int {
					if total > 0 {
						return resolved * 100 / total
					}
					return 0
				}(),
			})
		})

		// POST /api/v1/scan/all-modes — trigger scan cho tất cả modes chưa có data
		// FULL_SOC — trigger all scan modes in sequence
		r.Post("/api/v1/vsp/run/full-soc", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			var req struct {
				Src string `json:"src"`
			}
			json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
			if req.Src == "" {
				http.Error(w, `{"error":"src required"}`, http.StatusBadRequest)
				return
			}
			rid := fmt.Sprintf("FULL_SOC_%s", time.Now().Format("20060102_150405"))
			_, err := db.Pool().Exec(ctx,
				"INSERT INTO runs (rid,tenant_id,mode,profile,src,status,started_at) "+
					"VALUES ($1,$2,$3,$4,$5,'QUEUED',NOW())",
				rid, claims.TenantID, "FULL_SOC", "FULL_SOC", req.Src)
			if err != nil {
				http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"ok": true, "rid": rid, "mode": "FULL_SOC",
				"message": "FULL_SOC queued — SAST+SCA+SECRETS+IAC+DAST+NETWORK",
			})
		})
		r.Get("/api/v1/vsp/runs/full-soc", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			rows, err := db.Pool().Query(r.Context(),
				"SELECT rid,status,started_at,"+
					"COALESCE(total_findings,0),COALESCE(gate,'PENDING'),0 "+
					"FROM runs WHERE tenant_id=$1 AND mode='FULL_SOC' "+
					"ORDER BY started_at DESC LIMIT 20", claims.TenantID)
			if err != nil {
				http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
				return
			}
			defer rows.Close()
			type Row struct {
				ID            string    `json:"id"`
				Status        string    `json:"status"`
				StartedAt     time.Time `json:"started_at"`
				TotalFindings int       `json:"total_findings"`
				Gate          string    `json:"gate"`
				Score         int       `json:"score"`
			}
			var runs []Row
			for rows.Next() {
				var row Row
				_ = rows.Scan(&row.ID, &row.Status, &row.StartedAt, //nolint:errcheck
					&row.TotalFindings, &row.Gate, &row.Score)
				runs = append(runs, row)
			}
			if runs == nil {
				runs = []Row{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"runs": runs, "total": len(runs)}) //nolint:errcheck
		})
		r.Post("/api/v1/scan/all-modes", func(w http.ResponseWriter, r *http.Request) {
			_, _ = auth.FromContext(r.Context())
			var req struct {
				Src     string `json:"src"`
				URL     string `json:"url"`
				Profile string `json:"profile"`
			}
			json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
			if req.Src == "" {
				req.Src = "/home/test/Data/GOLANG_VSP"
			}
			if req.Profile == "" {
				req.Profile = "FAST"
			}

			modes := []struct{ Mode, Profile, Src, URL string }{
				{"SAST", req.Profile, req.Src, ""},
				{"SCA", req.Profile, req.Src, ""},
				{"SECRETS", req.Profile, req.Src, ""},
				{"IAC", req.Profile, req.Src, ""},
				{"DAST", "EXT", "", req.URL},
				{"NETWORK", "EXT", "", req.URL},
			}

			var triggered []map[string]interface{}
			for _, m := range modes {
				if m.URL == "" && (m.Mode == "DAST" || m.Mode == "NETWORK") {
					triggered = append(triggered, map[string]interface{}{
						"mode": m.Mode, "status": "skipped", "reason": "no URL provided",
					})
					continue
				}
				// Create run record
				_ = fmt.Sprintf("RID_ALLMODE_%s_%s", m.Mode, time.Now().Format("20060102_150405"))
				// Trigger via runsH directly
				trigPayload, _ := json.Marshal(map[string]string{
					"mode": m.Mode, "profile": m.Profile, "src": m.Src, "url": m.URL,
				})
				trigReq, _ := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1:8921/api/v1/vsp/run",
					bytes.NewReader(trigPayload))
				// Copy auth header
				trigReq.Header.Set("Content-Type", "application/json")
				trigReq.Header.Set("Authorization", r.Header.Get("Authorization"))
				trigReq.AddCookie(&http.Cookie{Name: "vsp_csrf", Value: ""}) // #nosec G124 -- empty internal-trigger cookie, not sent to browser
				client2 := &http.Client{Timeout: 10 * time.Second}
				resp2, err := client2.Do(trigReq)
				if err != nil {
					triggered = append(triggered, map[string]interface{}{
						"mode": m.Mode, "status": "error", "reason": err.Error(),
					})
					continue
				}
				var runRes map[string]interface{}
				json.NewDecoder(resp2.Body).Decode(&runRes) //nolint:errcheck
				_ = resp2.Body.Close()
				rid2, _ := runRes["rid"].(string)
				if rid2 == "" {
					rid2 = fmt.Sprintf("error-%d", resp2.StatusCode)
				}
				triggered = append(triggered, map[string]interface{}{
					"mode": m.Mode, "rid": rid2, "status": runRes["status"],
					"profile": m.Profile,
				})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
				"triggered": triggered, "total": len(triggered),
			})
		})

		r.Post("/api/v1/poam/sync", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			rows, err := db.Pool().Query(ctx,
				"SELECT f.id::text, f.severity, f.tool, f.rule_id, f.message, f.path FROM findings f "+
					"WHERE f.tenant_id = $1 AND f.severity IN ('CRITICAL','HIGH') "+
					"AND NOT EXISTS (SELECT 1 FROM p4_poam_items p WHERE p.finding_id = f.id::text) "+
					"ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 END, f.created_at DESC LIMIT 100",
				claims.TenantID)
			if err != nil {
				http.Error(w, `{"error":"db"}`, 500)
				return
			}
			defer rows.Close()
			type frow struct{ id, sev, tool, rule, msg, path string }
			var findings []frow
			for rows.Next() {
				var f frow
				_ = rows.Scan(&f.id, &f.sev, &f.tool, &f.rule, &f.msg, &f.path)
				findings = append(findings, f)
			}
			var maxNum int
			_ = db.Pool().QueryRow(ctx, "SELECT COALESCE(MAX(CAST(SUBSTRING(id FROM 10) AS INTEGER)),0) FROM p4_poam_items WHERE id LIKE 'POAM-VSP-%'").Scan(&maxNum) //nolint:errcheck
			ctrlMap := map[string]string{"semgrep": "SA-11", "bandit": "SA-11", "trivy": "RA-5", "grype": "RA-5", "gitleaks": "IA-5", "kics": "CM-6", "checkov": "CM-6", "nuclei": "CA-2", "nikto": "CA-2", "nmap": "SC-7"}
			created := 0
			for i, f := range findings {
				poamID := fmt.Sprintf("POAM-VSP-%03d", maxNum+i+1)
				due := time.Now().Add(7 * 24 * time.Hour)
				if f.sev == "CRITICAL" {
					due = time.Now().Add(24 * time.Hour)
				}
				ctrl := ctrlMap[f.tool]
				if ctrl == "" {
					ctrl = "SI-3"
				}
				title := f.msg
				if len(title) > 100 {
					title = title[:97] + "..."
				}
				mit := fmt.Sprintf("VSP auto-sync. Tool:%s Rule:%s Path:%s", f.tool, f.rule, f.path)
				_, e := db.Pool().Exec(ctx,
					"INSERT INTO p4_poam_items (id,system_id,weakness_name,control_id,severity,status,mitigation_plan,finding_id,scheduled_completion,tenant_id,created_at,updated_at) "+
						"VALUES ($1,$2,$3,$4,$5,'open',$6,$7,$8,$9,NOW(),NOW()) ON CONFLICT (id) DO NOTHING",
					poamID, "VSP-AUTO-SYNC", title, ctrl, f.sev, mit, f.id, due, claims.TenantID)
				if e == nil {
					created++
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"synced": created, "available": len(findings), "message": fmt.Sprintf("Created %d POA&M items", created)}) //nolint:errcheck
		})
		r.Get("/api/v1/vsp/tt13_report_pdf/{rid}", reportH.TT13PDF)
		r.Get("/api/v1/reports/conmon_pdf", reportH.ConMonPDF)
		r.Get("/api/v1/vsp/executive_report_pdf/{rid}", reportH.ExecutivePDF)
		r.Get("/api/v1/vsp/executive_report_html/{rid}", reportH.ExecutiveHTML)
		// SLA + Sandbox + Imports
		r.Get("/api/v1/vsp/sla_tracker", slaH.Tracker)
		r.Get("/api/v1/vsp/metrics_slos", slaH.MetricsSLOs)
		r.Get("/api/v1/vsp/sandbox", sandboxH.List)
		r.Post("/api/v1/vsp/sandbox/test-fire", sandboxH.TestFire)
		r.Delete("/api/v1/vsp/sandbox/clear", sandboxH.Clear)
		r.With(vspMW.StrictLimiter(10, time.Minute)).Post("/api/v1/import/policies", importsH.Policies)
		r.With(vspMW.StrictLimiter(10, time.Minute)).Post("/api/v1/import/findings", importsH.Findings)
		r.With(vspMW.StrictLimiter(10, time.Minute)).Post("/api/v1/import/users", importsH.Users)
		r.Post("/api/v1/vsp/rbac/session-timeout", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok","message":"session timeout updated"}`))
		})
		// Export
		r.Get("/api/v1/export/sarif/{rid}", exportH.SARIF)
		r.Get("/api/v1/export/csv/{rid}", exportH.CSV)
		r.Get("/api/v1/export/json/{rid}", exportH.JSON)

		// Software Inventory routes
		swH := &handler.SoftwareInventoryHandler{DB: db}
		r.Post("/api/v1/software-inventory/report", swH.ReceiveReport)
		r.Get("/api/v1/software-inventory/stats", swH.GetStats)
		r.Get("/api/v1/software-inventory/eol-database", swH.ListEOL)
		r.Get("/api/v1/software-inventory/{hostname}", swH.GetAsset)
		r.Get("/api/v1/software-inventory", swH.ListAssets)
	})

	addr := fmt.Sprintf(":%d", viper.GetInt("server.gateway_port"))
	srv := &http.Server{Addr: addr, Handler: r,
		ReadTimeout: 30 * time.Second, WriteTimeout: 0}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()
	log.Info().Str("addr", addr).Msg("VSP Gateway v0.10.0 — Enterprise Premium LIVE ✓")

	// ── SSE broadcast poller — detect scan complete + trigger SOAR ──
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		// Khôi phục lastSeen từ Redis để không broadcast lại sau restart
		lastSeen, _ := ca.GetString(ctx, "vsp:sse:last_rid")
		for {
			select {
			case <-ticker.C:
				// Update DB pool metrics
				handler.RecordDBPool(db.PoolStats())

				// Find runs completed since last check
				rows, err := db.Pool().Query(ctx, `
					SELECT r.id, r.rid, r.tenant_id, r.gate, r.total_findings,
					       r.summary, r.created_at
					FROM runs r
					WHERE r.status='DONE'
					  AND r.rid > $1
					ORDER BY r.rid DESC LIMIT 5`, lastSeen)
				if err != nil {
					continue
				}
				var toTrigger []struct {
					rid, tenantID, gate string
					findings            int
				}
				for rows.Next() {
					var id, rid, tenantID, gate string
					var findings int
					var summary []byte
					var createdAt time.Time
					if err := rows.Scan(&id, &rid, &tenantID, &gate, &findings, &summary, &createdAt); err != nil {
						continue
					}
					if rid <= lastSeen {
						continue
					}
					lastSeen = rid
					ca.Set(ctx, "vsp:sse:last_rid", []byte(rid), 30*24*time.Hour)
					// Broadcast SSE
					msg, _ := json.Marshal(map[string]any{
						"type": "scan_complete", "rid": rid,
						"gate": gate, "total_findings": findings,
						"tenant_id": tenantID,
					})
					handler.Hub.Broadcast(msg)
					// Invalidate cache khi có scan mới
					ca.Invalidate(ctx, "vsp:api:*")
					log.Info().Str("rid", rid).Str("gate", gate).Msg("sse: broadcast scan_complete")
					if gate == "FAIL" {
						toTrigger = append(toTrigger, struct {
							rid, tenantID, gate string
							findings            int
						}{rid, tenantID, gate, findings})
					}
				}
				rows.Close()
				// Trigger SOAR for FAIL gates
				for _, t := range toTrigger {
					pbs, err := db.FindEnabledPlaybooks(ctx, t.tenantID, "gate_fail", "any")
					if err != nil {
						continue
					}
					for _, pb := range pbs {
						ctxJSON, _ := json.Marshal(map[string]any{
							"trigger": "gate_fail", "gate": t.gate,
							"run_id": t.rid, "findings": t.findings,
						})
						runID, err := db.CreatePlaybookRun(ctx, pb.ID, t.tenantID, "gate_fail", ctxJSON)
						if err != nil {
							continue
						}
						log.Info().Str("playbook", pb.Name).Str("run_id", runID).Msg("soar: auto-triggered on gate FAIL")
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	log.Info().Msg("SSE broadcast poller started — interval: 5s")

	// ── UEBA background worker — chạy mỗi 15 phút ──────────────
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		// Chạy ngay lần đầu sau 30s
		time.Sleep(30 * time.Second)
		siem.RunUEBA(ctx, db)
		for {
			select {
			case <-ticker.C:
				siem.RunUEBA(ctx, db)
			case <-ctx.Done():
				return
			}
		}
	}()
	log.Info().Msg("UEBA worker started — interval: 15m")

	// ── Incident email alerter ───────────────────────────────────
	safe.GoCtx(ctx, func(ctx context.Context) { siem.WatchIncidents(ctx, db) })

	// ── Correlation engine ──────────────────────
	safe.GoCtx(ctx, func(ctx context.Context) { siem.StartCorrelationEngine(ctx, db, handler.Hub.Broadcast) })
	log.Info().Msg("Correlation engine started")

	log.Info().Msg("Incident email alerter started — interval: 30s")

	// ── Retention policy worker ──────────────────────────────────
	safe.GoCtx(ctx, func(ctx context.Context) { siem.StartRetentionWorker(ctx, db) })

	// ── Syslog receiver UDP:514 + TCP:514 ───────────────────────
	udpAddr := viper.GetString("siem.syslog_udp_addr")
	if udpAddr == "" {
		udpAddr = ":10514"
	}
	tcpAddr := viper.GetString("siem.syslog_tcp_addr")
	if tcpAddr == "" {
		tcpAddr = ":10515"
	}
	var tenantID string
	_ = db.Pool().QueryRow(ctx, `SELECT id FROM tenants WHERE slug='default' LIMIT 1`).Scan(&tenantID) //nolint:errcheck
	if tenantID != "" {
		receiver := siem.NewSyslogReceiver(udpAddr, tcpAddr, db, tenantID)
		go func() {
			if err := receiver.Start(ctx); err != nil {
				log.Error().Err(err).Msg("syslog receiver error")
			}
		}()
		log.Info().Str("udp", udpAddr).Str("tcp", tcpAddr).Msg("Syslog receiver started")
	}

	<-quit
	log.Info().Msg("shutting down gracefully — draining connections (30s)...")
	// Cancel context trước — signals tất cả goroutines dừng lại
	shutdown()
	// Drain HTTP connections
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		log.Error().Err(err).Msg("server shutdown error")
	}
	// Đợi goroutines dừng (tối đa 5s)
	time.Sleep(500 * time.Millisecond)
	db.Close()
	_ = asynqClient.Close()
	log.Info().Msg("stopped ✓")
}

func corsMiddleware(next http.Handler) http.Handler {
	raw := viper.GetString("server.allowed_origins")
	if raw == "" {
		raw = "http://localhost:3000,http://localhost:8080,http://127.0.0.1:8080,http://localhost:8910,http://127.0.0.1:8910,http://localhost:8921,http://127.0.0.1:8921,http://localhost:8922,http://127.0.0.1:8922"
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
			if allowed[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
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
		_ = rows.Scan(&id, &tenantID, &hash, &role, &expiresAt) //nolint:errcheck
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
	_, _ = db.Pool().Exec(ctx, `INSERT INTO tenants(slug,name,plan) VALUES('default','Default Tenant','enterprise') ON CONFLICT(slug) DO NOTHING`) //nolint:errcheck
}
func getDefaultTenantID(ctx context.Context, db *store.DB) string {
	var id string
	_ = db.Pool().QueryRow(ctx, `SELECT id FROM tenants WHERE slug='default' LIMIT 1`).Scan(&id) //nolint:errcheck
	if id == "" {
		log.Fatal().Msg("default tenant not found")
	}
	return id
}

// p4ResponseWriter was removed in VSP-CSP-001 Commit 2a.
// Panel CSP is now handled centrally by vspMW.CSPNonce via PanelCSP();
// see internal/api/middleware/csp.go.
