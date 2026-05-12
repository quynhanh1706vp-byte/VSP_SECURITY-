package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vsp/platform/internal/autopr"
	"github.com/vsp/platform/internal/container"

	"database/sql"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"

	"crypto/tls"

	"path/filepath"
	"strconv"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/vsp/platform/internal/agentic"
	"github.com/vsp/platform/internal/api/handler"
	vspMW "github.com/vsp/platform/internal/api/middleware"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/autofix"
	"github.com/vsp/platform/internal/billing"
	"github.com/vsp/platform/internal/cache"
	"github.com/vsp/platform/internal/conmon"
	"github.com/vsp/platform/internal/handlers"
	"github.com/vsp/platform/internal/i18n"
	"github.com/vsp/platform/internal/llm"
	"github.com/vsp/platform/internal/migrate"
	"github.com/vsp/platform/internal/netcap"
	"github.com/vsp/platform/internal/notify"
	"github.com/vsp/platform/internal/pipeline"
	"github.com/vsp/platform/internal/poam"
	"github.com/vsp/platform/internal/safe"
	"github.com/vsp/platform/internal/scheduler"
	"github.com/vsp/platform/internal/secrets"
	"github.com/vsp/platform/internal/siem"
	"github.com/vsp/platform/internal/soar"
	"github.com/vsp/platform/internal/store"
	"github.com/vsp/platform/internal/telemetry"
	"github.com/vsp/platform/internal/ticket"
)

// init đăng ký MIME types đúng để Chrome strict MIME checking không chặn
// .js/.css. http.ServeFile và http.FileServer đều dùng mime.TypeByExtension().
func init() {
	mime.AddExtensionType(".js", "application/javascript; charset=utf-8")
	mime.AddExtensionType(".mjs", "application/javascript; charset=utf-8")
	mime.AddExtensionType(".css", "text/css; charset=utf-8")
	mime.AddExtensionType(".html", "text/html; charset=utf-8")
	mime.AddExtensionType(".json", "application/json; charset=utf-8")
	mime.AddExtensionType(".svg", "image/svg+xml")
	mime.AddExtensionType(".woff", "font/woff")
	mime.AddExtensionType(".woff2", "font/woff2")
	mime.AddExtensionType(".map", "application/json")
}

var startTime = time.Now()

// wsBroadcaster bridges handler.Hub to soar.Broadcaster interface.
type wsBroadcaster struct{}

func (wsBroadcaster) Broadcast(msg []byte) { handler.Hub.Broadcast(msg) }

// llmDBAdapter satisfies llm.PgxQuerier using whatever db.Pool() returns.
// Uses interface{} + reflection-free type assertion on the methods we need.
type llmDBAdapter struct{ raw interface{} }

func (a llmDBAdapter) QueryRow(ctx context.Context, sqlStr string, args ...interface{}) llm.PgxRow {
	type qr interface {
		QueryRow(ctx context.Context, sql string, args ...interface{}) interface{ Scan(...interface{}) error }
	}
	if p, ok := a.raw.(qr); ok {
		return p.QueryRow(ctx, sqlStr, args...)
	}
	return errRow{fmt.Errorf("db pool type does not implement QueryRow(ctx, sql, args...)")}
}

func (a llmDBAdapter) Exec(ctx context.Context, sqlStr string, args ...interface{}) (interface{}, error) {
	type ex interface {
		Exec(ctx context.Context, sql string, args ...interface{}) (interface{}, error)
	}
	if p, ok := a.raw.(ex); ok {
		return p.Exec(ctx, sqlStr, args...)
	}
	return nil, fmt.Errorf("db pool type does not implement Exec(ctx, sql, args...)")
}

type errRow struct{ err error }

func (e errRow) Scan(...interface{}) error { return e.err }

func main() {
	// ─── H3.N: Initialize LLM provider + policy ─────────────────────
	var llmProvider llm.Provider
	var llmPolicy *llm.Policy
	if os.Getenv("LLM_ENABLED") == "true" {
		provider := os.Getenv("LLM_PROVIDER")
		if provider == "" {
			provider = "ollama"
		}
		baseURL := os.Getenv("LLM_BASE_URL")
		if baseURL == "" {
			baseURL = "http://127.0.0.1:11434"
		}
		model := os.Getenv("LLM_MODEL")
		if model == "" {
			model = "deepseek-coder-v2:16b"
		}
		timeoutSec := 30
		if s := os.Getenv("LLM_TIMEOUT_SECONDS"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				timeoutSec = n
			}
		}
		switch provider {
		case "ollama":
			if p, err := llm.NewOllamaProvider(baseURL, model, timeoutSec); err == nil {
				llmProvider = p
				log.Printf("[H3.N] LLM provider: ollama @ %s (model=%s)", baseURL, model)
			} else {
				log.Printf("[H3.N] LLM provider init failed: %v", err)
			}
		default:
			log.Printf("[H3.N] LLM provider %q not implemented yet, only ollama", provider)
		}
		policyPath := os.Getenv("LLM_POLICY_PATH")
		llmPolicy = llm.LoadPolicy(policyPath)
	} else {
		llmPolicy = llm.LoadPolicy("") // default-allow with secrets blocked
		log.Printf("[H3.N] LLM disabled (LLM_ENABLED!=true) — using templates only")
	}
	_ = llmProvider // suppress unused warning if no LLM routes use it

	_ = llmPolicy

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
	// NoColor when stderr isn't a TTY (CI, journald, file redirects).
	// ANSI colour codes break structured-log shippers (and L27.28.4.1).
	stderrFI, _ := os.Stderr.Stat()
	stderrIsTTY := stderrFI != nil && (stderrFI.Mode()&os.ModeCharDevice) != 0
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    !stderrIsTTY,
	})

	ctx, shutdown := context.WithCancel(context.Background())
	defer shutdown()
	// DSN: prefer secrets provider when configured. The secrets package
	// returns the env-loaded value when VSP_SECRETS_PROVIDER is unset, so
	// this is a no-op in dev. In production with VSP_SECRETS_PROVIDER=vault
	// the DSN comes from Vault rather than .env on the host.
	dsn := viper.GetString("database.url")
	if sp, sErr := secrets.Default(); sErr == nil {
		if v, err := sp.Get("db_url"); err == nil && v != "" {
			dsn = v
			log.Info().Str("source", sp.Source()).Msg("db_url loaded from secrets provider")
		}
	}
	db, err := store.New(ctx, dsn)
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

	// ─── [H3.T] Agentic Autofix orchestrator ─────────────────────────
	agenticRepoRoot := os.Getenv("VSP_REPO_ROOT")
	if agenticRepoRoot == "" {
		agenticRepoRoot = "/home/test/Data/GOLANG_VSP"
	}
	agenticTools := agentic.NewToolBox(agenticRepoRoot)
	agenticOrch := agentic.NewOrchestrator(p4DB, agenticTools)
	agenticOrch.Telem = telemetry.G() // [H3.X] wire real telemetry (was noopTelemetry)
	agenticHandlers := agentic.NewHandlerSet(agenticOrch)

	// ─── [H3.X] Health trackers cho workers ───
	agenticHealth := handler.NewWorkerHealth(2 * time.Minute)
	remediationHealth := handler.NewWorkerHealth(7 * time.Minute)
	healthH := &handler.HealthHandler{
		AgenticHealth:     agenticHealth,
		RemediationHealth: remediationHealth,
	}

	// ─── [H3.U] Remediation Worker — auto-populate items from findings ─
	autofix.StartRemediationWorker(ctx, p4DB, remediationHealth)

	// ─── [H3.O] Pre-compute Worker ───────────────────────────────────
	// Background worker pre-computes AI fixes for CRITICAL/HIGH code findings
	// after each scan completes, eliminating 25-40s "Loading diff..." UX latency.
	// Uses p4DB (*sql.DB) — same connection style as all H3.N handlers.
	var precomputeWorker *autofix.PrecomputeWorker
	if os.Getenv("LLM_ENABLED") == "true" && os.Getenv("LLM_PRECOMPUTE_ENABLED") != "false" {
		if llmProvider != nil && llmPolicy != nil && p4DB != nil {
			precomputeWorker = autofix.NewPrecomputeWorker(p4DB, llmProvider, llmPolicy)
			if precomputeWorker != nil {
				precomputeWorker.SetHealth(agenticHealth)
				ctxWorker, cancelWorker := context.WithCancel(context.Background())
				go precomputeWorker.Run(ctxWorker)

				// ── H3.S SLA scheduler (auto-PR creation) ─────────────

				slaScheduler := autopr.NewSLAScheduler(p4DB)

				slaScheduler.Start(ctxWorker)
				log.Printf("[H3.O] Pre-compute worker initialized")
				_ = cancelWorker
			}
		}
	}
	_ = precomputeWorker

	if skErr := initOrLoadSigningKey(p4SQLDB); skErr != nil {
		log.Printf("[main] WARN: supply chain signing key init failed: %v", skErr)
	}
	defaultTID := getDefaultTenantID(ctx, db)

	// JWT secret: prefer the configured secrets provider (Vault if
	// VSP_SECRETS_PROVIDER=vault). Falls back to the viper-loaded value
	// (which itself reads JWT_SECRET env). The provider abstraction lets
	// production deployments centralise rotation in Vault without code
	// changes — see internal/secrets/.
	jwtSecret := viper.GetString("auth.jwt_secret")
	if sp, sErr := secrets.Default(); sErr == nil {
		if v, err := sp.Get("jwt"); err == nil && v != "" {
			jwtSecret = v
			log.Info().Str("source", sp.Source()).Msg("jwt secret loaded from secrets provider")
		}
		// If running on Vault, kick off the rotator so subsequent KV
		// writes flow into the cache without restart. Other providers
		// (env) are no-ops for rotation by definition.
		if vp, ok := sp.(*secrets.VaultProvider); ok {
			vp.StartRotator(ctx, 15*time.Minute)
		}
	}
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

	// ── Token blacklist (Redis DB 1) — wires JWT revocation into middleware ──
	tokenBlacklist := auth.NewTokenBlacklist(redisAddr, redisPass)
	auth.SetBlacklist(tokenBlacklist)
	log.Info().Str("redis", redisAddr).Msg("token blacklist initialized (Redis DB 1)")

	// Anomaly-driven session revocation: scans audit_log every minute for
	// impossible-travel + rapid-IP-rotation patterns and revokes all
	// tokens for the affected user.
	go auth.NewAnomalyDetector(db.Pool(), tokenBlacklist, time.Minute).Run(ctx)

	authH := &handler.Auth{
		DB:         db,
		JWTSecret:  jwtSecret,
		JWTTTL:     jwtTTL,
		DefaultTID: defaultTID,
		IPLock:     auth.NewIPLockout(),
	}
	handler.SetJWTSecret(jwtSecret)
	// L27 2026-05-09: warm Prometheus CounterVec series at startup so
	// /metrics exposes them from boot. CounterVec doesn't emit a
	// series until at least one label combination has been Inc()'d,
	// so a freshly-restarted gateway has no auth/login metric until
	// someone tries to log in. Operators alerting on rate(...) or
	// increase(...) over a window need the series to exist immediately.
	for _, r := range []string{"success", "failed", "locked", "ip_locked", "mfa_failed"} {
		handler.LoginAttempts.WithLabelValues(r).Add(0)
	}
	handler.AuditChainBreaks.Add(0)
	// L9 2026-05-09: wire the slug→UUID resolver auth middleware uses
	// to canonicalise Claims.TenantID before handlers see it.
	auth.SetClaimsTenantResolver(func(ctx context.Context, raw string) string {
		if raw == "" {
			return ""
		}
		var id string
		_ = db.Pool().QueryRow(ctx,
			`SELECT id::text FROM tenants WHERE slug=$1 LIMIT 1`, raw).Scan(&id)
		return id
	})
	// L5 fix: SSE subscribers must scope by tenant UUID, not slug. Wire
	// a slug→UUID resolver so JWT claims (which carry "default") match
	// broadcast messages (which carry the UUID). Inline lookup here —
	// resolveTenantUUID lives in package handler so we replicate the
	// 1-line query rather than exporting it.
	handler.SetSSETenantResolver(func(claim string) string {
		if claim == "" {
			return ""
		}
		// Heuristic: 36-char hyphenated string is already a UUID.
		if len(claim) == 36 && strings.Count(claim, "-") == 4 {
			return claim
		}
		var id string
		_ = db.Pool().QueryRow(context.Background(),
			`SELECT id::text FROM tenants WHERE slug=$1 LIMIT 1`, claim).Scan(&id)
		if id == "" {
			return claim
		}
		return id
	})
	usersH := &handler.Users{DB: db}
	mfaH := &handler.MFA{DB: db}
	apiKeysH := &handler.APIKeys{DB: db}
	toolConfigH := &handler.ToolConfig{DB: db}
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
	agentsH := &handler.Agents{DB: db}
	soarH := &handler.SOAR{DB: db}

	// ───────── SOAR Engine v2 (Phase 2.1.B+C) ─────────
	soarRepoKey := os.Getenv("VSP_REPO_KEY")
	if soarRepoKey == "" {
		log.Fatal().Msg("VSP_REPO_KEY env var required for SOAR vault")
	}
	soarSecretsStore := &soar.SecretsStoreAdapter{DB: db}
	soarVault, err := soar.NewVault(soarSecretsStore, soarRepoKey)
	if err != nil {
		log.Fatal().Err(err).Msg("init SOAR vault")
	}
	soarSandbox := soar.NewSandbox()
	soarDispatcher := soar.NewDispatcher()
	soarDispatcher.RegisterDefault()
	soarNotifier := notify.New(notify.Config{
		SlackDefaultWebhook:   viper.GetString("integrations.slack_webhook"),
		DiscordDefaultWebhook: viper.GetString("integrations.discord_webhook"),
		TeamsDefaultWebhook:   viper.GetString("integrations.teams_webhook"),
	})
	soarTicketer := ticket.New(ticket.Config{
		JiraBaseURL:         viper.GetString("integrations.jira_url"),
		JiraEmail:           viper.GetString("integrations.jira_email"),
		JiraAPIToken:        viper.GetString("integrations.jira_token"),
		PagerDutyRoutingKey: viper.GetString("integrations.pagerduty_key"),
		GitHubBaseURL:       viper.GetString("integrations.github_base_url"),
		GitHubToken:         viper.GetString("integrations.github_token"),
		GitHubRepo:          viper.GetString("integrations.github_repo"),
	})
	soar.RegisterIOExecutors(soarDispatcher, soar.NewSafeHTTPClient(), soarNotifier, soarTicketer)
	soar.RegisterFlowExecutors(soarDispatcher, soarSandbox, nil, nil)

	// Register 7 SOAR metrics
	for name, meta := range soar.DescribeMetrics() {
		telemetry.G().Describe(name, meta[0], meta[1])
	}

	soarAdapter := &soar.StoreAdapter{DB: db}
	soarEngine, err := soar.New(soar.EngineConfig{
		Store:         soarAdapter,
		Dispatcher:    soarDispatcher,
		Vault:         soarVault,
		Sandbox:       soarSandbox,
		Broadcaster:   wsBroadcaster{},
		Metrics:       telemetry.NewSOARPromAdapter(),
		MaxConcurrent: 100,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("init SOAR engine")
	}
	soarManager := soar.NewManager(soarEngine, soarAdapter)
	soarV2H := &handler.SOARv2{
		DB:      db,
		Manager: soarManager,
		Vault:   soarVault,
		Engine:  soarEngine,
	}
	log.Info().Msg("SOAR engine initialized")

	logSrcH := &handler.LogSources{DB: db}
	tiH := &handler.ThreatIntel{DB: db}
	complianceH := &handler.Compliance{DB: db}
	govH := &handler.Governance{DB: db}
	exportH := &handler.Export{DB: db}
	reportH := &handler.Report{DB: db}
	sbomH := &handler.SBOM{DB: db}
	// PHASE3G-HANDLERS-BEGIN
	oscalModelsH := &handler.OSCALModels{DB: db}
	// PHASE3G-HANDLERS-END
	// PHASE3F-HANDLERS-BEGIN
	oscalPackageH := &handler.OSCALPackage{DB: db}
	// PHASE3F-HANDLERS-END
	// PHASE3-HANDLERS-BEGIN
	supplyChainH := &handler.SupplyChain{DB: db}
	cisaAttestH := &handler.CISAAttestation{DB: db}
	// PHASE3-HANDLERS-END
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
	// VSP_PATCH_PERF_03 — global per-IP rate limiter disabled.
	// Reason: dashboard burst of ~70 req/s exhausted 600/min bucket within
	// seconds, causing prolonged 429 storms. Defense remains via JWT auth,
	// CSRF protect, 4MB body limit, 60s timeout, and nginx layer.
	// To re-enable, uncomment both this and r.Use(rl.Middleware) below.
	_ = vspMW.NewRateLimiter // keep package imported
	// rl := vspMW.NewRateLimiter(600, time.Minute)

	// ── Router ────────────────────────────────────────────────────
	r := chi.NewRouter()
	// Custom 404 / 405 — chi's default emits `text/plain` "404 page not
	// found", which breaks JSON-routing clients (they expected the
	// {"error":"..."} envelope every other 4xx uses). L45.1.1 caught
	// this on /api/v1/scheduler/jobs.
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"route not found"}`))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"error":"method not allowed"}`))
	})
	// Strip trailing slash before route matching (so /api/x/ → /api/x)
	r.Use(chimw.StripSlashes)
	r.Use(chimw.RequestID)
	// L23 2026-05-09: chimw.RealIP blindly trusts X-Forwarded-For /
	// X-Real-IP and rewrites r.RemoteAddr. That lets a direct attacker
	// (no proxy in front) set XFF: 127.0.0.1 and impersonate loopback,
	// bypassing every IP-based gate downstream — /debug/* loopback gate,
	// /metrics localhost gate, IPLockout (each request appears to come
	// from a different IP). Wrap RealIP so it only fires when the
	// IMMEDIATE TCP source is in a trusted-proxy allow-list.
	//
	// Default trusted proxies: loopback. Operators behind a LB extend
	// via VSP_TRUSTED_PROXIES (comma-separated CIDRs).
	r.Use(trustedRealIP(viper.GetString("server.trusted_proxies")))
	r.Use(i18n.Middleware) // resolves locale from query/header/accept-language
	r.Use(vspMW.CSPNonce)
	r.Use(vspMW.CSRFProtect)
	r.Use(vspMW.RequestLogger)
	// L27 2026-05-09: per-request latency + outcome metrics. Wires
	// vsp_api_request_duration_seconds histogram (declared in
	// internal/api/handler/metrics.go) so operators can see RPS, P99,
	// status mix per route. Path label is intentionally coarse
	// (chi RoutePattern, not raw URL) to keep cardinality bounded.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, req.ProtoMajor)
			next.ServeHTTP(ww, req)
			// L53 cardinality fix: use chi's RoutePattern when chi
			// matched a route, sentinel for non-matched. Also
			// collapse status code to class (2xx/3xx/4xx/5xx) —
			// individual status codes blew the metric to 1600+
			// series. With class-collapse we go from
			//   routes × methods × ~20-statuses × 11-buckets
			//   to
			//   routes × methods × 5-classes × 11-buckets
			rctx := chi.RouteContext(req.Context())
			path := "<no-route>"
			if rctx != nil && rctx.RoutePattern() != "" {
				path = rctx.RoutePattern()
			}
			statusClass := fmt.Sprintf("%dxx", ww.Status()/100)
			handler.APIRequestDuration.WithLabelValues(
				req.Method, path, statusClass,
			).Observe(time.Since(start).Seconds())
		})
	})
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(60 * time.Second))
	// L17.18.3.1 slowloris hard kill: srv.ReadTimeout in some chi
	// configurations doesn't fire reliably during slow-body streaming
	// because middlewares can buffer or hijack the body. Belt-and-
	// braces: pre-read the entire request body into memory with a
	// short context deadline, then hand a buffered NopCloser to the
	// handler. A client trickling 1 byte/sec gets cut off here, not
	// after the handler returns.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Limit request body to 4MB to block DoS (was the previous
			// middleware in this slot).
			r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
			// Skip body pre-read for streaming methods / SSE / proxy
			// passthroughs — they need the live body.
			if r.Method == http.MethodGet || r.Method == http.MethodHead ||
				r.Method == http.MethodOptions || r.ContentLength <= 0 ||
				strings.HasPrefix(r.URL.Path, "/api/sc") ||
				strings.HasPrefix(r.URL.Path, "/api/dast") ||
				strings.HasPrefix(r.URL.Path, "/api/swinv") ||
				strings.HasPrefix(r.URL.Path, "/api/email") {
				next.ServeHTTP(w, r)
				return
			}
			done := make(chan struct{})
			var (
				buf []byte
				err error
			)
			go func() {
				buf, err = io.ReadAll(r.Body)
				close(done)
			}()
			select {
			case <-done:
				if err != nil {
					http.Error(w, "request body read failed", http.StatusBadRequest)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(buf))
				next.ServeHTTP(w, r)
			case <-time.After(15 * time.Second):
				// Connection:close + r.Close aren't enough — Go's
				// finishRequest() still tries to drain the slow body
				// before the conn close lands, giving the attacker
				// another ~ContentLength seconds. Hijack the conn and
				// kill it ourselves so the close is immediate.
				if hj, ok := w.(http.Hijacker); ok {
					if conn, _, err := hj.Hijack(); err == nil {
						_, _ = conn.Write([]byte(
							"HTTP/1.1 408 Request Timeout\r\n" +
								"Content-Length: 0\r\n" +
								"Connection: close\r\n\r\n"))
						_ = conn.Close()
						return
					}
				}
				// Hijack unavailable — best-effort close-marker.
				w.Header().Set("Connection", "close")
				r.Close = true
				http.Error(w, "request body read timed out", http.StatusRequestTimeout)
			}
		})
	})
	r.Use(corsMiddleware)
	// VSP_PATCH_PERF_03 — disabled: r.Use(rl.Middleware)

	// [H3.X] Custom telemetry registry — agentic + remediation metrics
	r.Handle("/metrics/vsp", telemetry.G())

	// ─── [H3.X] Health routes — mounted at root, after global middlewares ───
	// CSRF only checks POST/PUT/DELETE so GET /health/* passes naturally.
	// No auth required — these are liveness probes for monitoring.
	r.Get("/health/agentic", healthH.Agentic)
	r.Get("/health/remediation", healthH.Remediation)
	r.Get("/health/deep", healthH.DeepCheck(p4DB))

	// pprof + expvar — gated by source IP. Pre-L15 the comment claimed
	// "protected by authMw + network policy" but neither was actually
	// applied: r.Mount("/debug", ...) sits in the no-auth public group,
	// so /debug/pprof/heap, /goroutine, /vars were anonymous-readable
	// in every non-production deploy. pprof leaks goroutine stacks
	// (which contain in-flight JWT tokens, request bodies, and tenant
	// data); expvar leaks process command line + memstats. Same
	// loopback gate as /metrics below — only the host itself can scrape.
	if viper.GetString("server.env") != "production" {
		debugMux := http.DefaultServeMux
		r.HandleFunc("/debug/*", func(w http.ResponseWriter, req *http.Request) {
			ip := req.RemoteAddr
			if idx := strings.LastIndex(ip, ":"); idx >= 0 {
				ip = ip[:idx]
			}
			ip = strings.Trim(ip, "[]")
			if ip != "127.0.0.1" && ip != "::1" && !strings.HasPrefix(ip, "10.") &&
				!strings.HasPrefix(ip, "192.168.") && !strings.HasPrefix(ip, "172.16.") {
				http.Error(w, "forbidden — /debug/* restricted to loopback/internal", http.StatusForbidden)
				return
			}
			debugMux.ServeHTTP(w, req)
		})
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

	// Endpoint Agent self-auth routes — agents present X-Agent-Key per request.
	// These are public at the chi level but the handlers themselves verify
	// the agent key against agents.api_key_hash and reject unknown keys.
	r.Post("/api/v1/agents/heartbeat", agentsH.Heartbeat)
	r.Post("/api/v1/agents/inventory", agentsH.Inventory)

	authMwBase := auth.Middleware(jwtSecret, keyStore)
	residencyMw := vspMW.Residency(db.Pool())
	// Wrap the auth middleware so the resolved tenant UUID is propagated
	// onto the request context. The pgxpool's BeforeAcquire hook reads
	// this and sets `vsp.tenant_id` GUC for RLS policies (see
	// migration 037 + internal/store/rls.go). Then apply residency
	// enforcement which needs the tenant context to look up the
	// configured region.
	authMw := func(next http.Handler) http.Handler {
		return authMwBase(residencyMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c, ok := auth.FromContext(r.Context()); ok && c.TenantID != "" {
				tid := c.TenantID
				if !looksLikeUUIDLocal(tid) {
					if u := resolveTenantUUIDLocal(r.Context(), db, tid); u != "" {
						tid = u
					}
				}
				r = r.WithContext(store.SetTenantContext(r.Context(), tid))
			}
			next.ServeHTTP(w, r)
		})))
	}

	// PRO plan gating — reads tenants.plan with a 5-min cache.
	// Apply requirePro to any route that should be reserved for paid tiers
	// (PRO + Enterprise). Returns 402 with {required_plan, current_plan} JSON
	// so the frontend overlay can prompt the upgrade flow.
	proResolver := vspMW.NewDBPlanResolver(db.Pool(), 5*time.Minute)
	requirePro := vspMW.RequirePro(proResolver)

	r.With(authMw).Get("/api/v1/auth/check", authH.Check) // session check — validates cookie

	// SSE — cookie-based auth (no ?token= in URL — prevents log leakage)
	r.With(authMw).Get("/api/v1/events", handler.SSEHandler)

	// ── Landing page (Phase 4 go-to-market) ──
	// Marketing landing page, referenced from nginx location block:
	//   location ~ ^/(landing|onboarding|admin|docs|p4|static)
	// Nginx forwards these paths to this gateway; without these routes
	// it 404s (no filesystem fallback for /static/*.html).
	r.Get("/landing", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/landing.html")
	})
	r.Get("/landing.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/landing.html")
	})

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

	r.Get("/vsp_pro_100.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_pro_100.js")
	})
	r.Get("/vsp_pro_cwpp_realapi.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_pro_cwpp_realapi.js")
	})
	r.Get("/vsp_pro_supplychain_realapi.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_pro_supplychain_realapi.js")
	})
	// realapi companion for cspm / secrets_vault / tenants / observe panels.
	// Adds 402-aware fetch + "Upgrade to PRO" overlay + Configure sub-panel.
	r.Get("/vsp_pro_realapi.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_pro_realapi.js")
	})
	// Sidebar collapsible sections — chevron toggle per nav-section.
	r.Get("/vsp_sidebar_collapse.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_sidebar_collapse.js")
	})
	// SIEM panel companion — runs inside each /panels/<id>.html iframe and
	// reaches back into the parent VSP_PRO via same-origin window.parent
	// to render Configure / Notifications buttons. Schemas live in the JS.
	r.Get("/vsp_siem_companion.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_siem_companion.js")
	})
	r.Get("/vsp_sw_inventory_panel.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_sw_inventory_panel.js")
	})
	r.Get("/vsp_scheduler_panel.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_scheduler_panel.js")
	})
	r.Get("/vsp_email_panel.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_email_panel.js")
	})
	r.Get("/vsp_dast_panel.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_dast_panel.js")
	})

	// FEAT-04: vsp_uxstates.js — shared skeleton/empty/error UI module
	r.Get("/vsp_uxstates.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_uxstates.js")
	})

	// Serve JS assets from ./static/js/ (dom-safe.js, vsp_iframe_bootstrap.js, etc.)
	// These scripts are referenced by index.html and panel HTML files.
	r.Get("/static/js/*", http.StripPrefix("/static/js/",
		http.FileServer(http.Dir("./static/js/"))).ServeHTTP)

	// FEAT-20c PATCH APPLIED — Serve UX patch scripts from ./static/patches/
	// Allows monkey-patch JS files (feat-20-ai-analyst.js etc.) to be loaded
	// without recompiling gateway. Drop new patches into static/patches/.
	r.Get("/static/patches/*", http.StripPrefix("/static/patches/",
		http.FileServer(http.Dir("./static/patches/"))).ServeHTTP)

	// Serve general static assets from ./static/ (inject_ux_v1.1.js, inject_ux_v1.1.css, etc.)
	r.Get("/static/*", http.StripPrefix("/static/",
		http.FileServer(http.Dir("./static/"))).ServeHTTP)

	// RFC 9116 — security.txt at /.well-known/security.txt + the
	// disclosure policy doc. Anonymous, no rate-limit.
	r.Get("/.well-known/*", http.StripPrefix("/.well-known/",
		http.FileServer(http.Dir("./static/.well-known/"))).ServeHTTP)

	// Public Trust Center page (Sprint 9.B1). Anonymous, cached at
	// the static layer; consumes anonymous /api/v1/status endpoint
	// for live operational status.
	//
	// Serve both /trust and /trust/* — chimw.StripSlashes strips the
	// trailing slash so /trust/ becomes /trust, and a redirect-back
	// would create an infinite loop. Instead /trust serves index.html
	// directly.
	r.Get("/trust", func(w http.ResponseWriter, req *http.Request) {
		http.ServeFile(w, req, "./static/trust/index.html")
	})
	r.Get("/trust/*", http.StripPrefix("/trust/",
		http.FileServer(http.Dir("./static/trust/"))).ServeHTTP)

	// Sprint 8.3 status endpoint — anonymous, top-level so
	// external status-page consumers (Statuspage.io, Cachet,
	// Atlassian Statuspage) can poll without credentials.
	// Caching (30s Cache-Control) handled inside the handler.
	publicStatusH := handler.NewStatusPublic(db)
	r.Get("/api/v1/status", publicStatusH.Get)

	// Scanner availability — anon-readable so the FE "New Scan" modal
	// can grey out tools whose binary isn't on $PATH. Drives the "26/26
	// ready" badge in the dashboard header.
	r.Get("/api/v1/scanners/health", func(w http.ResponseWriter, req *http.Request) {
		available, results := pipeline.HealthSnapshot()
		w.Header().Set("Cache-Control", "public, max-age=15")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"available":         available,
			"expected_full_soc": 26,
			"tools":             results,
		})
	})

	// VSP own-SBOM (Sprint 10.5) — anonymous, cached 1h.
	// Path convention matches OpenSSF Scorecard auto-discovery.
	selfSBOMH := handler.NewSelfSBOM()
	r.Get("/sbom.cyclonedx.json", selfSBOMH.CycloneDX)
	r.Get("/sbom.spdx.json", selfSBOMH.SPDX)

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

	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/favicon.ico")
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
	r.Get("/api/p4/oscal", p4AuthMiddleware(tiH.OSCALIndex))
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

	// Probe scanner binaries once at boot so the operator sees the
	// "X / 26 dispatchable" line in startup logs. This catches an
	// under-provisioned image before users see partial FULL_SOC runs.
	pipeline.ProbeScannerBinaries()
	netCapH := handler.NewNetCapHandler(netCapEngine)
	// Auto-start on best available interface — disabled by default.
	// NetCap auto-start requires CAP_NET_RAW capability which most deploys don't grant.
	// Engine is still registered with pipeline (line above) for on-demand use by
	// NETWORK/FULL_SOC scan modes, and REST API /api/v1/netcap/start remains available
	// for manual triggering. Set NETCAP_AUTO_START=true to enable boot-time capture.
	if os.Getenv("NETCAP_AUTO_START") == "true" {
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
				return
			}
			ctxNC, cancelNC := context.WithCancel(context.Background())
			_ = cancelNC // cancelled when goroutine exits via engine.Stop()
			netCapEngine.StartTsharkDecoder(ctxNC, iface)
			log.Info().Str("iface", iface).Msg("[NetCap] auto-capture started")
		}()
	} else {
		log.Info().Msg("[NetCap] auto-start disabled (set NETCAP_AUTO_START=true to enable)")
	}
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
	// ConMon handler (used inside auth route group below)
	conmonH := handler.NewConMonHandler(p4DB)
	conmonH.SetAuditDB(db) // L8: enable audit emit on ConMon write paths

	// G37: ConMon FedRAMP template routes
	r.Get("/api/p4/conmon/template/asr", p4AuthMiddleware(conmonH.RenderASR))
	r.Get("/api/p4/conmon/template/qar", p4AuthMiddleware(conmonH.RenderQAR))
	r.Get("/api/p4/conmon/template/mcmr", p4AuthMiddleware(conmonH.RenderMCMR))

	// ─── Phase 5.1: ConMon scheduler goroutine ───────────────────
	// Wires the existing ConMon CRUD layer to actual pipeline execution.
	// Each tick (60s), schedules with next_run_at <= now() are triggered
	// via runsH.EnqueueDirect — same code path used by manual /scan calls
	// and the existing schedEngine. Tenant + target are taken from the
	// schedule row; mode is mapped through pipeline.Mode/Profile types.
	conmonRunTrigger := func(ctx context.Context, tenantID, mode, target string) (string, int64, error) {
		// Use the RID_SCHED_* prefix so the scheduler can later
		// correlate this run with other cron-fired runs in the
		// history table — same convention as scheduler.go line 67.
		rid := fmt.Sprintf("RID_SCHED_%s_conmon", time.Now().Format("20060102_150405"))
		runsH.EnqueueDirect(rid, tenantID, pipeline.Mode(mode), pipeline.Profile("default"), target, "")
		// The legacy int64 ID is always 0 (runs.id is UUID). The RID
		// string is what the worker's post-scan hook will use to find
		// this conmon_schedule and fill its last_verdict — see
		// scheduler.go:163 (writes last_run_rid) +
		// pipeline/worker.go (UPDATE conmon_schedules WHERE last_run_rid).
		return rid, 0, nil
	}
	conmonSched := conmon.NewScheduler(p4DB, conmonRunTrigger)
	go conmonSched.Start(ctx)
	log.Info().Dur("tick", conmonSched.TickInterval).Msg("ConMon scheduler started")
	aiH := handler.NewAIAdvisorHandler(p4DB,
		viper.GetString("anthropic.api_key"),
		viper.GetBool("airgap.enabled"))
	aiH.SetAuditDB(db) // L8: enable audit emit on Feedback
	ssoOIDCH := handler.NewSSOOIDCHandler(p4DB,
		jwtSecret,
		jwtTTL,
		auth.IssueJWT,
	)
	// ─── SSO public endpoints (no auth required) — Phase 4.5.3 ───
	r.Get("/api/v1/auth/sso/login", ssoOIDCH.Login)
	r.Get("/api/v1/auth/sso/callback", ssoOIDCH.Callback)

	r.Group(func(r chi.Router) {
		r.Use(authMw)
		// VSP_PATCH_PERF_02 — per-user rate limit disabled on /api/v1/* group.
		// Reason: dashboard burst (~70 req in <1s during boot) exceeded 3000/min bucket
		// because limiter has no burst capacity. Defense remains via JWT authMw + CSRF +
		// tenant isolation. /api/v1/auth/login still rate-limited separately for
		// brute-force protection (see auth route registration).
		// To re-enable: uncomment the line below and adjust the limit.
		// r.Use(vspMW.NewUserRateLimiter(3000, time.Minute)) // per-user: 3000 req/min

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
			// PRO gating — adding/removing users is a tenant-management
			// concern, free tier stays read-only.
			r.With(requirePro).Post("/api/v1/admin/users", usersH.Create)
			r.With(requirePro).Delete("/api/v1/admin/users/{id}", usersH.Delete)
			r.Get("/api/v1/admin/api-keys", apiKeysH.List)
			r.Post("/api/v1/admin/api-keys", apiKeysH.Create)
			r.Delete("/api/v1/admin/api-keys/{id}", apiKeysH.Delete)
			r.Get("/api/v1/admin/tenants", usersH.ListAllTenants)
			r.Post("/api/v1/admin/tenants", usersH.CreateTenant)
			r.Put("/api/v1/admin/tenants/{id}/plan", usersH.UpdatePlan)
		})

		// Scan
		r.Post("/api/v1/vsp/run", runsH.Trigger)
		r.Post("/api/v1/vsp/run/{rid}/cancel", runsH.Cancel)
		r.Get("/api/v1/vsp/run/latest", runsH.Latest)
		r.Get("/api/v1/vsp/run/{rid}", runsH.Get)
		r.Get("/api/v1/vsp/run/{rid}/log", runsH.Log)
		r.Get("/api/v1/vsp/run/{rid}/tail", runsH.Tail) // SSE live-tail
		r.Get("/api/v1/vsp/runs", runsH.List)
		r.Get("/api/v1/vsp/runs/index", runsH.Index)
		// Alias for the detail endpoint — FE callers (cicd.html:2699
		// remediation status poll) historically used the plural form
		// /api/v1/vsp/runs/{rid} where the canonical route is the
		// singular /api/v1/vsp/run/{rid}. Same handler, both spellings
		// work. Cheaper than chasing every FE call site.
		r.Get("/api/v1/vsp/runs/{rid}", runsH.Get)
		r.With(ca.Middleware("runs-index", 10*time.Second)).Get("/api/v1/vsp/runs/index", runsH.Index)
		// ── Batch scan ──────────────────────────────────────────────
		batchH := newBatchHandler(db, runsH)
		r.With(vspMW.StrictLimiter(5, time.Minute)).Post("/api/v1/vsp/batch", batchH.Submit)
		r.Get("/api/v1/vsp/batches", batchH.ListAll)
		r.Get("/api/v1/vsp/batch/{batch_id}", batchH.Status)
		r.Delete("/api/v1/vsp/batch/{batch_id}", batchH.Cancel)
		r.Get("/api/v1/vsp/findings", findingsH.List)
		r.With(ca.Middleware("findings-summary", 15*time.Second)).Get("/api/v1/vsp/findings/summary", findingsH.Summary)
		// VSP_PATCH_F1_ROUTES_BEGIN
		r.Post("/api/v1/vulns/bulk", handleVulnsBulk)
		r.Post("/api/v1/vulns/bulk/undo", handleVulnsBulkUndo)
		// VSP_PATCH_F1_ROUTES_END
		// ─── ConMon (Continuous Monitoring) — Phase 4.5.1 ─────────────
		r.Get("/api/v1/conmon/schedules", conmonH.Schedules)
		r.Post("/api/v1/conmon/schedules", conmonH.Schedules)
		r.Get("/api/v1/conmon/deviations", conmonH.Deviations)
		r.Get("/api/v1/conmon/cadence", conmonH.CadenceStatus)
		r.Post("/api/v1/conmon/deviations/{id}/acknowledge", conmonH.AckDeviation)
		// ─── AI Compliance Advisor — Phase 4.5.2 ─────────────────────
		// LLM-backed answer endpoint: PRO-gated (every call costs LLM tokens).
		// Read-only endpoints (mode + cache stats + feedback) stay free so
		// the panel can render even on the starter plan.
		r.With(requirePro).Post("/api/v1/ai/advise", aiH.Advise)
		r.Get("/api/v1/ai/mode", aiH.Mode)
		r.Get("/api/v1/ai/cache/stats", aiH.CacheStats)
		r.Post("/api/v1/ai/feedback/{id}", aiH.Feedback)
		// ─── SSO Provider Admin — Phase 4.5.3 ─────────────────────────
		// PRO feature: SSO / SAML provider configuration.
		// Reading existing providers is allowed for any auth'd user (so the
		// login screen can render available IdPs); mutations require PRO.
		r.Get("/api/v1/sso/providers", ssoOIDCH.Providers)
		r.With(requirePro).Post("/api/v1/sso/providers", ssoOIDCH.Providers)
		r.With(requirePro).Put("/api/v1/sso/providers/{id}", ssoOIDCH.ProviderByID)
		r.With(requirePro).Delete("/api/v1/sso/providers/{id}", ssoOIDCH.ProviderByID)

		// ─── Cloud Security Posture Management — PRO feature ────────────
		// Real persistence in cspm_accounts / cspm_findings / cspm_config
		// (migration 020). Replaces the prior in-memory aggregator mock.
		cspmH := handler.NewCSPM(db)
		r.With(requirePro).Get("/api/v1/cspm/accounts", cspmH.ListAccounts)
		r.With(requirePro).Post("/api/v1/cspm/accounts", cspmH.CreateAccount)
		r.With(requirePro).Delete("/api/v1/cspm/accounts/{id}", cspmH.DeleteAccount)
		r.With(requirePro).Post("/api/v1/cspm/accounts/{id}/sync", cspmH.SyncAccount)
		r.With(requirePro).Get("/api/v1/cspm/findings", cspmH.ListFindings)
		r.With(requirePro).Get("/api/v1/cspm/findings/{id}", cspmH.GetFinding)
		r.With(requirePro).Post("/api/v1/cspm/findings/{id}/status", cspmH.UpdateFindingStatus)
		r.With(requirePro).Get("/api/v1/cspm/posture", cspmH.Posture)
		r.With(requirePro).Get("/api/v1/cspm/config", cspmH.GetConfig)
		r.With(requirePro).Put("/api/v1/cspm/config", cspmH.UpdateConfig)
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
		// PRO panels — tenant quota + observability config (view-details overlays).
		proPanels := handler.NewProPanels(db)
		r.With(requirePro).Get("/api/v1/tenants/quota", proPanels.TenantQuota)
		r.With(requirePro).Get("/api/v1/observability/config", proPanels.ObservabilityConfigGet)
		r.With(requirePro).Put("/api/v1/observability/config", proPanels.ObservabilityConfigPut)
		// Per-tenant config endpoints for the remaining PRO sidebar panels.
		// Each panel's "Configure" overlay reads/writes one of these.
		r.With(requirePro).Get("/api/v1/cwpp/config", proPanels.CWPPConfigGet)
		r.With(requirePro).Put("/api/v1/cwpp/config", proPanels.CWPPConfigPut)
		r.With(requirePro).Get("/api/v1/autofix/config", proPanels.AutofixConfigGet)
		r.With(requirePro).Put("/api/v1/autofix/config", proPanels.AutofixConfigPut)
		r.With(requirePro).Get("/api/v1/supply-chain/config", proPanels.SupplyChainConfigGet)
		r.With(requirePro).Put("/api/v1/supply-chain/config", proPanels.SupplyChainConfigPut)
		r.With(requirePro).Get("/api/v1/sbom/config", proPanels.SBOMConfigGet)
		r.With(requirePro).Put("/api/v1/sbom/config", proPanels.SBOMConfigPut)
		r.With(requirePro).Get("/api/v1/sso/config", proPanels.SSOConfigGet)
		r.With(requirePro).Put("/api/v1/sso/config", proPanels.SSOConfigPut)
		// Cross-panel notifications: Slack/Teams/webhook/email/PagerDuty.
		// Configure once per tenant; every PRO panel can reference these channels.
		r.With(requirePro).Get("/api/v1/notifications/config", proPanels.NotificationConfigGet)
		r.With(requirePro).Put("/api/v1/notifications/config", proPanels.NotificationConfigPut)
		r.With(requirePro).Post("/api/v1/notifications/test", proPanels.NotificationTest)
		r.With(requirePro).Get("/api/v1/notifications/log", proPanels.NotificationLog)
		r.With(requirePro).Get("/api/v1/notifications/dlq", proPanels.NotificationDLQ)
		r.With(requirePro).Post("/api/v1/notifications/dlq/retry", proPanels.NotificationDLQRetry)

		// Generic per-tenant config store for the 12 SIEM panels.
		// Each panel's Configure form serialises into feature_config.config
		// (JSONB). PRO-gated so business tier customers can persist tuning
		// (UEBA thresholds, hunt queries, etc.) while free tier reads defaults.
		featureCfgH := handler.NewFeatureConfig(db)
		r.With(requirePro).Get("/api/v1/features/{id}/config", featureCfgH.Get)
		r.With(requirePro).Put("/api/v1/features/{id}/config", featureCfgH.Put)

		// Analytics summary — server-side aggregation for the Analytics panel.
		// Free tier keeps the client-side fallback (loops over /vsp/runs/index);
		// PRO offloads heavy aggregation to Postgres + serves trend data
		// without shipping thousands of run rows over the wire.
		analyticsH := handler.NewAnalytics(db)
		r.With(requirePro).Get("/api/v1/analytics/summary", analyticsH.Summary)
		// Billing
		r.Get("/api/v1/billing/status", billingH.Status)
		r.With(vspMW.StrictLimiter(5, time.Minute)).Post("/api/v1/billing/checkout", billingH.CreateCheckout)
		r.Post("/api/v1/audit/verify", auditH.Verify)
		r.Post("/api/v1/audit/repair", auditH.Repair)

		// SIEM (PRO)
		r.With(requirePro).Get("/api/v1/siem/webhooks", siemH.List)

		// ── Correlation engine (PRO) ─────────────────────────────────
		r.With(requirePro).Get("/api/v1/correlation/rules", corrH.ListRules)
		r.With(requirePro).Post("/api/v1/correlation/rules", corrH.CreateRule)
		r.With(requirePro).Post("/api/v1/correlation/rules/{id}/toggle", corrH.ToggleRule)
		r.With(requirePro).Delete("/api/v1/correlation/rules/{id}", corrH.DeleteRule)
		r.With(requirePro).Get("/api/v1/correlation/incidents", corrH.ListIncidents)
		r.With(requirePro).Get("/api/v1/correlation/incidents/{id}", corrH.GetIncident)
		r.With(requirePro).Post("/api/v1/correlation/incidents/{id}/resolve", corrH.ResolveIncident)
		r.With(requirePro).Patch("/api/v1/correlation/incidents/{id}/status", corrH.ResolveIncident)
		r.With(requirePro).Post("/api/v1/correlation/incidents", corrH.CreateIncident)

		// ── AI Analyst smart mock ──────────────────────────────── (PRO-gated)
		r.With(requirePro).Post("/api/v1/ai/analyze", func(w http.ResponseWriter, r *http.Request) {
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

		// ── AI Analyst proxy ──────────────────────────────────── (PRO-gated)
		r.With(requirePro).Post("/api/v1/ai/chat", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit
			if err != nil {
				http.Error(w, "bad request", 400)
				return
			}

			// Offline / no-key fallback. Without ANTHROPIC_API_KEY the proxy
			// would forward the request and Anthropic returns 401 — which
			// looks like an auth failure to the user. Serve a graceful
			// canned response that the panel renders inline so the iframe
			// is usable in air-gapped deployments and demo environments.
			apiKey := viper.GetString("anthropic.api_key")
			// Treat the placeholder value as unset — env files in dev/demo
			// envs ship with `ANTHROPIC_API_KEY=REPLACE_WITH_REAL_KEY`, which
			// is non-empty so the old check let the request fly to Anthropic
			// and get rejected with a confusing 401 "invalid x-api-key".
			if apiKey == "" || strings.HasPrefix(apiKey, "REPLACE_") || apiKey == "your-key-here" {
				_ = body // body intentionally read above for size validation
				offline := `{"id":"vsp-offline","type":"message","role":"assistant",` +
					`"model":"vsp-offline-fallback","content":[{"type":"text",` +
					`"text":"VSP AI Analyst — offline mode\n\nANTHROPIC_API_KEY is not configured on the gateway. ` +
					`Set it in /etc/vsp/env.production and restart vsp-gateway to enable live LLM responses.\n\n` +
					`Tenant data (findings, incidents, SIEM context) is still streaming live from Postgres — see the panel sidebar for current state."}],` +
					`"stop_reason":"end_turn","usage":{"input_tokens":0,"output_tokens":0}}`
				_, _ = w.Write([]byte(offline))
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
			req.Header.Set("x-api-key", apiKey)
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
		// /analyze runs the full ML re-baseline (expensive) — PRO-gated.
		// Read-only endpoints stay free so the panel renders even on starter.
		r.With(requirePro).Get("/api/v1/ueba/anomalies", uebaH.ListAnomalies)
		r.With(requirePro).Post("/api/v1/ueba/analyze", uebaH.Analyze)
		r.With(requirePro).Get("/api/v1/ueba/baseline", uebaH.Baseline)
		r.With(requirePro).Get("/api/v1/ueba/timeline", uebaH.Timeline)

		// ── Threat Hunt — saved queries + result history (PRO) ───────────
		// Free-tier ad-hoc search via /api/v1/logs/hunt remains available;
		// these endpoints add the persistence layer for repeat hunting.
		threatHuntH := handler.NewThreatHunt(db)
		r.With(requirePro).Get("/api/v1/threat-hunt/queries", threatHuntH.ListQueries)
		r.With(requirePro).Post("/api/v1/threat-hunt/queries", threatHuntH.CreateQuery)
		r.With(requirePro).Delete("/api/v1/threat-hunt/queries/{id}", threatHuntH.DeleteQuery)
		r.With(requirePro).Post("/api/v1/threat-hunt/queries/{id}/run", threatHuntH.RunQuery)
		r.With(requirePro).Get("/api/v1/threat-hunt/results", threatHuntH.ListResults)

		// ── Asset inventory ─────────────────────────────────────
		r.Get("/api/v1/assets", assetsH.List)
		r.Post("/api/v1/assets", assetsH.Create)
		r.Get("/api/v1/assets/summary", assetsH.Summary)
		r.Get("/api/v1/assets/{id}/findings", assetsH.Findings)

		// Endpoint Agents (JWT-protected — UI manages enrollments)
		r.Post("/api/v1/agents/enroll", agentsH.Enroll)
		r.Get("/api/v1/agents", agentsH.List)
		r.Get("/api/v1/agents/{id}", agentsH.Get)
		r.Delete("/api/v1/agents/{id}", agentsH.Revoke)

		// ── SOAR playbooks (PRO) ────────────────────────────────
		r.With(requirePro).Get("/api/v1/soar/playbooks", soarH.ListPlaybooks)
		r.With(requirePro).Post("/api/v1/soar/playbooks", soarH.CreatePlaybook)
		r.With(requirePro).Post("/api/v1/soar/playbooks/{id}/toggle", soarH.TogglePlaybook)
		r.With(requirePro).Post("/api/v1/soar/playbooks/{id}/run", soarV2H.ExecutePlaybook)
		r.With(requirePro).Post("/api/v1/soar/trigger", soarH.Trigger)
		r.With(requirePro).Get("/api/v1/soar/runs", soarH.ListRuns)

		// ── SOAR engine v2 (Phase 2.1.C) ────────────────────────
		// PRO gating — playbook execution is the expensive path (sandbox spin-up,
		// outbound HTTP, secret resolution). Test mode is also gated since it
		// runs the same engine in dry-run mode.
		r.With(requirePro).Post("/api/v1/soar/playbooks/{id}/execute", soarV2H.ExecutePlaybook)
		r.With(requirePro).Post("/api/v1/soar/playbooks/{id}/test", soarV2H.TestPlaybook)
		r.With(requirePro).Get("/api/v1/soar/runs/{id}", soarV2H.GetRun)
		r.With(requirePro).Post("/api/v1/soar/runs/{id}/cancel", soarV2H.CancelRun)
		r.With(requirePro).Get("/api/v1/soar/playbooks/{id}/versions", soarV2H.ListPlaybookVersions)
		r.With(requirePro).Post("/api/v1/soar/playbooks/{id}/version/{n}/rollback", soarV2H.RollbackVersion)
		r.With(requirePro).Get("/api/v1/soar/approvals/pending", soarV2H.ListPendingApprovals)
		r.With(requirePro).Post("/api/v1/soar/approvals/{id}/decide", soarV2H.DecideApproval)
		// PRO feature: Secret Vault.
		// Basic CRUD + new "view details" endpoints (rotate, audit log,
		// per-tenant config, summary). All gated by requirePro so starter
		// tenants get 402 Payment Required.
		r.With(requirePro).Get("/api/v1/soar/secrets", soarV2H.ListSecrets)
		r.With(requirePro).Post("/api/v1/soar/secrets", soarV2H.CreateSecret)
		r.With(requirePro).Delete("/api/v1/soar/secrets/{name}", soarV2H.DeleteSecret)
		r.With(requirePro).Get("/api/v1/soar/secrets/audit", soarV2H.SecretAuditLog)
		r.With(requirePro).Get("/api/v1/soar/secrets/summary", soarV2H.VaultSummary)
		r.With(requirePro).Get("/api/v1/soar/secrets/config", soarV2H.GetVaultConfig)
		r.With(requirePro).Put("/api/v1/soar/secrets/config", soarV2H.UpdateVaultConfig)
		r.With(requirePro).Get("/api/v1/soar/secrets/{name}", soarV2H.GetSecretMeta)
		r.With(requirePro).Post("/api/v1/soar/secrets/{name}/rotate", soarV2H.RotateSecret)

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
		// PRO gating — pulling external feeds + CISA KEV refresh costs egress
		// bandwidth and rate-limit budget against upstream providers.
		r.With(requirePro).Post("/api/v1/ti/feeds/sync", tiH.SyncFeeds)
		r.Get("/api/v1/ti/enrich", tiH.Enrich)
		r.With(vspMW.StrictLimiter(10, time.Minute)).Post("/api/v1/ti/enrich/batch", tiH.EnrichBatch)
		r.Get("/api/v1/vsp/findings/dedup", tiH.DedupFindings)
		r.Get("/api/v1/vsp/findings/chains", tiH.ExploitChains)
		r.Post("/api/v1/ai/analyze/findings", tiH.SemanticAnalyze)
		r.Post("/api/v1/ti/secret/check", tiH.CheckSecret)
		r.With(vspMW.StrictLimiter(20, time.Minute)).Post("/api/v1/ti/secret/check/batch", tiH.CheckSecretBatch)
		r.Get("/api/v1/compliance/license", tiH.LicenseCompliance)
		r.Get("/api/v1/ti/stats", tiH.Stats)
		r.Get("/api/v1/sw/component/{hash}/threat", tiH.ComponentThreat)
		r.Get("/api/v1/integrations/virustotal/stats", tiH.VTStats)

		// UI Real Data — query actual DB tables
		r.Get("/api/v1/integrations", tiH.IntegrationsList)
		r.Post("/api/v1/integrations/{provider}/test-pr-comment", tiH.IntegrationsTestProvider)
		r.Post("/api/v1/integrations/{provider}/test-ticket", tiH.IntegrationsTestProvider)
		r.Get("/api/v1/settings/scan-config", tiH.SettingsScanConfig)
		r.Get("/api/v1/settings/dast-targets", tiH.SettingsDastTargets)

		// Phase B Step 2 — per-tenant tool enable/disable
		r.Get("/api/v1/settings/tool-config", toolConfigH.Get)
		r.Put("/api/v1/settings/tool-config", toolConfigH.Update)
		r.Post("/api/v1/settings/tool-config/reset", toolConfigH.Reset)
		r.Get("/api/v1/sbom", tiH.SBOMIndex)

		// UI 404 FIX: stub routes (return empty/ok)
		r.Get("/api/v1/settings/dast-targets", tiH.UISTubSettings)
		r.Get("/api/v1/settings/scan-config", tiH.UISTubSettings)
		r.Get("/api/v1/integrations", tiH.UISTubIntegrationsList)
		r.Post("/api/v1/integrations/{provider}/test-pr-comment", tiH.UISTubIntegrationsTest)
		r.Post("/api/v1/integrations/{provider}/test-ticket", tiH.UISTubIntegrationsTest)
		r.Post("/api/v1/sw/report", tiH.UISTubSwReport)
		r.With(requirePro).Post("/api/v1/ti/kev/refresh", tiH.RefreshKEV)
		r.With(requirePro).Post("/api/v1/siem/webhooks", siemH.Create)
		r.With(requirePro).Delete("/api/v1/siem/webhooks/{id}", siemH.Delete)
		r.With(requirePro).Post("/api/v1/siem/webhooks/{id}/test", siemH.Test)

		// Compliance
		r.Get("/api/v1/compliance/fedramp", complianceH.FedRAMP)
		r.Get("/api/v1/compliance/cmmc", complianceH.CMMC)
		r.Get("/api/v1/compliance/oscal/ar", complianceH.OSCALAR)
		r.Get("/api/v1/compliance/oscal/poam", complianceH.OSCALPOAM)

		// Compliance evidence file storage
		evidenceH := handler.NewComplianceEvidence(db)
		r.Post("/api/v1/compliance/evidence", evidenceH.Upload)
		r.Get("/api/v1/compliance/evidence", evidenceH.List)
		r.Get("/api/v1/compliance/evidence/{id}", evidenceH.Download)
		r.Delete("/api/v1/compliance/evidence/{id}", evidenceH.Delete)

		// DORA metrics (DevOps Research & Assessment) — derived from runs/autofix_pr/ir_incidents
		doraH := handler.NewDORA(db)
		r.With(requirePro).Get("/api/v1/dora", doraH.Get)

		// cATO (continuous Authority To Operate) — posture + admin toggle
		catoH := handler.NewCATO(db)
		r.With(requirePro).Get("/api/v1/cato", catoH.Get)
		r.With(requirePro).Post("/api/v1/cato/toggle", catoH.Toggle)

		// MITRE ATT&CK heatmap — coverage view from finding signatures
		attackH := handler.NewAttack(db)
		r.With(requirePro).Get("/api/v1/attack/heatmap", attackH.Heatmap)

		// SLSA L3 readiness — signed run provenance (DSSE / in-toto v1)
		r.Post("/api/v1/runs/{rid}/provenance", handleRunProvenanceGenerate)
		r.Get("/api/v1/runs/{rid}/provenance", handleRunProvenanceGet)
		r.Get("/api/v1/runs/{rid}/provenance/verify", handleRunProvenanceVerify)

		// External Grafana embed — config + iframe URL builder
		grafanaH := handler.NewGrafana(db)
		r.With(requirePro).Get("/api/v1/grafana/config", grafanaH.GetConfig)
		r.With(requirePro).Post("/api/v1/grafana/config", grafanaH.SetConfig)
		r.With(requirePro).Get("/api/v1/grafana/embed-url", grafanaH.EmbedURL)

		// i18n locale preference
		localeH := handler.NewLocale(db)
		r.Get("/api/v1/locale", localeH.Get)
		r.Post("/api/v1/locale", localeH.Set)

		// Data residency (Decree 53/2022 + GDPR)
		residencyH := handler.NewResidency(db)
		r.Get("/api/v1/residency/config", residencyH.Get)
		r.Post("/api/v1/residency/config", residencyH.Set)
		r.Get("/api/v1/residency/violations", residencyH.Violations)

		// ConMon Score — real per-tenant continuous-monitoring score.
		// Replaces the demo "94/100" hardcoded in p4_compliance.html.
		conmonScoreH := handler.NewConMonScore(db)
		r.Get("/api/v1/conmon/score", conmonScoreH.Get)

		// KPI internal-consistency assertions (Sprint 7.5). CI scripts
		// poll this endpoint and treat HTTP 409 as a release blocker.
		kpiH := handler.NewKPISanity(db)
		r.Get("/api/v1/kpi/sanity", kpiH.Get)

		// Sprint 9 — Recognition uplift ────────────────────────────────
		// CISA SSDF self-attestation form auto-generator + executive sign
		ssdfH := handler.NewSSDFAttest(db)
		r.Get("/api/v1/cisa-attestation/ssdf/draft", ssdfH.Draft)
		r.Post("/api/v1/cisa-attestation/ssdf/{id}/sign", ssdfH.Sign)

		// NIST CSF 2.0 organisational profile
		csfH := handler.NewNISTCSF(db)
		r.Get("/api/v1/nist-csf/profile", csfH.Profile)

		// SOC 2 + ISO 27001 readiness mappings
		recH := handler.NewRecognition(db)
		r.Get("/api/v1/recognition/soc2-readiness", recH.SOC2Readiness)
		r.Get("/api/v1/recognition/iso27001-mapping", recH.ISO27001Mapping)

		// Annual / semi-annual transparency report (anon-readable)
		trH := handler.NewTransparency(db)
		r.Get("/api/v1/transparency/report", trH.Report)

		// Sigstore Rekor public attestation publish (admin only)
		r.Post("/api/v1/runs/{rid}/provenance/publish-rekor", handleRekorPublish)

		// Sprint 10 — additional framework mappings + SSP generator
		r.Get("/api/v1/recognition/pci-dss-mapping", recH.PCIDSSMapping)
		r.Get("/api/v1/recognition/nis2-mapping", recH.NIS2Mapping)
		r.Get("/api/v1/recognition/hitrust-mapping", recH.HITRUSTMapping)
		r.Get("/api/v1/recognition/ccpa-mapping", recH.CCPAMapping)

		sspH := handler.NewSSPGenerator(db)
		r.Get("/api/v1/compliance/ssp.md", sspH.Markdown)

		// Sprint 8 — 4.0 attainability scaffolding ────────────────────
		// VDP intake (anonymous POST, admin GET/transition)
		discloseH := handler.NewDisclosure(db)
		r.Post("/api/v1/security/disclose", discloseH.Submit) // anon
		r.Get("/api/v1/security/disclosures", discloseH.List)
		r.Post("/api/v1/security/disclosures/{id}/transition", discloseH.Transition)

		// Public status moved out of auth group — see line ~735 for
		// the anonymous registration. Sprint 8.3 originally registered
		// here by mistake which made external status-page consumers
		// (Statuspage, Cachet) get 401 instead of the JSON they expect.
		_ = handler.NewStatusPublic // keep symbol referenced

		// Quarterly improvement metrics (DSOMM L4 trend evidence)
		impH := handler.NewImprovement(db)
		r.Get("/api/v1/improvement/quarters", impH.Quarters)

		// Tabletop exercise registry
		tabH := handler.NewTabletop(db)
		r.Post("/api/v1/tabletop/exercises", tabH.Record)
		r.Get("/api/v1/tabletop/exercises", tabH.List)
		r.Get("/api/v1/tabletop/cadence", tabH.Cadence)

		// Auditor evidence bundle (admin only)
		bundleH := handler.NewAuditBundle(db)
		r.Get("/api/v1/audit/bundle", bundleH.Get)

		// WebAuthn / FIDO2 / Passkey
		// Wires up only when VSP_WEBAUTHN_RP_ID is configured. Otherwise we
		// log a one-line skip and continue — operators not yet running on
		// HTTPS shouldn't be forced to deal with WebAuthn errors.
		if waH, err := handler.NewWebAuthnHandler(db); err == nil && waH != nil {
			r.With(authMw).Post("/api/v1/auth/webauthn/register/begin", waH.RegisterBegin)
			r.With(authMw).Post("/api/v1/auth/webauthn/register/finish", waH.RegisterFinish)
			r.Post("/api/v1/auth/webauthn/login/begin", waH.LoginBegin)
			r.Post("/api/v1/auth/webauthn/login/finish", waH.LoginFinish)
			r.With(authMw).Get("/api/v1/auth/webauthn/credentials", waH.ListCredentials)
			r.With(authMw).Post("/api/v1/auth/webauthn/credentials/{id}/revoke", waH.RevokeCredential)
		} else {
			log.Info().Msg("webauthn: VSP_WEBAUTHN_RP_ID not set — passkey routes disabled")
		}

		// DSAR (GDPR Art. 15) + Right-to-Erasure (Art. 17 / PDPA Decree 13/2023)
		dsrH := handler.NewDSR(db)
		r.Post("/api/v1/data/export", dsrH.RequestExport)
		r.Get("/api/v1/data/exports/{id}", dsrH.GetExport)
		r.Post("/api/v1/data/erasure", dsrH.RequestErasure)
		r.Post("/api/v1/data/erasure/{id}/confirm", dsrH.ConfirmErasure)
		r.Post("/api/v1/data/erasure/{id}/cancel", dsrH.CancelErasure)
		r.Get("/api/v1/data/requests", dsrH.List)

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
		// ── Phase 1: workflow endpoints (added 2026-05-04) ──
		r.Post("/api/v1/remediation/finding/{finding_id}/transition", remediationH.Transition)
		r.Get("/api/v1/remediation/finding/{finding_id}/history", remediationH.History)
		r.Post("/api/v1/remediation/bulk", remediationH.Bulk)
		r.Get("/api/v1/remediation/kpis", remediationH.KPIs)
		r.Post("/api/v1/remediation/{rem_id}/comments", remediationH.AddComment)

		// PATCH /api/v1/remediation/finding/{finding_id}/status
		// Partial update: only fields present in body are written. Omitted fields
		// keep their existing DB values. Prevents data loss from zero-value clobber.
		r.Patch("/api/v1/remediation/finding/{finding_id}/status", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			fid := chi.URLParam(r, "finding_id")

			// Decode as raw map to detect which keys client actually sent
			var raw map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
				http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
				return
			}

			fields := make(map[string]any)
			validStatus := map[string]bool{"open": true, "in_progress": true, "fix_applied": true, "verifying": true, "verified": true, "fix_failed": true, "resolved": true, "accepted": true, "false_positive": true, "suppressed": true}

			if v, ok := raw["status"]; ok {
				var s string
				_ = json.Unmarshal(v, &s)
				if !validStatus[s] {
					http.Error(w, `{"error":"invalid status"}`, http.StatusBadRequest)
					return
				}
				fields["status"] = s
			}
			for _, col := range []string{"assignee", "priority", "ticket_url"} {
				if v, ok := raw[col]; ok {
					var s string
					_ = json.Unmarshal(v, &s)
					fields[col] = s
				}
			}
			// notes: support new "notes" key, fall back to legacy "comment"
			if v, ok := raw["notes"]; ok {
				var s string
				_ = json.Unmarshal(v, &s)
				fields["notes"] = s
			} else if v, ok := raw["comment"]; ok {
				var s string
				_ = json.Unmarshal(v, &s)
				fields["notes"] = s
			}

			if len(fields) == 0 {
				http.Error(w, `{"error":"no fields to update"}`, http.StatusBadRequest)
				return
			}

			rem, err := remediationH.DB.UpdateRemediationFields(r.Context(), fid, claims.TenantID, fields)
			if err != nil {
				http.Error(w, `{"error":"db error: `+err.Error()+`"}`, http.StatusInternalServerError)
				return
			}

			updatedKeys := make([]string, 0, len(fields))
			for k := range fields {
				updatedKeys = append(updatedKeys, k)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"ok": true, "finding_id": fid,
				"new_status": rem.Status, "resolved_at": rem.ResolvedAt,
				"updated_fields": updatedKeys,
			})
		})

		// ─── H3.M Quick Wins ─────────────────────────────────────────────
		// Stub routes for /api/v1/autofix/* and /api/v1/findings/{id}/diff.
		// These return placeholder JSON until handlers are wired in.
		// Once internal/handlers/* are imported, replace bodies with:
		//   handlers.FindingDiffHandler(db, ".")(w, req)
		//   handlers.LeaderboardHandler(db)(w, req)
		//   handlers.AutofixMetricsHandler(db)(w, req)

		// #8 Real diff preview — H3.N: with LLM fallback
		r.Get("/api/v1/findings/{id}/diff", func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()
			findingID := chi.URLParam(req, "id")
			w.Header().Set("Content-Type", "application/json")

			// Build response shell
			type diffResp struct {
				FindingID      string   `json:"finding_id"`
				FilePath       string   `json:"file_path"`
				LineStart      int      `json:"line_start"`
				LineEnd        int      `json:"line_end"`
				ContextBefore  []string `json:"context_before"`
				CurrentCode    []string `json:"current_code"`
				SuggestedFix   []string `json:"suggested_fix"`
				ContextAfter   []string `json:"context_after"`
				Rationale      string   `json:"rationale"`
				Confidence     string   `json:"confidence"`
				BreakingChange bool     `json:"breaking_change"`
				HasTemplate    bool     `json:"has_template"`
				Source         string   `json:"source"` // template|cache|llm|llm_failed|manual
				Provider       string   `json:"provider,omitempty"`
				Model          string   `json:"model,omitempty"`
				LatencyMs      int64    `json:"latency_ms,omitempty"`
			}
			resp := diffResp{FindingID: findingID, Source: "manual", Confidence: "manual"}

			// Lookup finding from DB (pgx)
			var path, ruleID, severity, message string
			var lineNum int
			err := db.Pool().QueryRow(ctx,
				`SELECT COALESCE(path,''), COALESCE(rule_id,''),
				        COALESCE(severity,''), COALESCE(message,''),
				        COALESCE(line_num, 0)
				   FROM findings WHERE id = $1`, findingID).
				Scan(&path, &ruleID, &severity, &message, &lineNum)
			if err != nil {
				resp.Rationale = "Finding not found"
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			resp.FilePath = path
			resp.LineStart = lineNum

			// Read source file (best-effort, ±5 lines)
			repoRoot := os.Getenv("VSP_REPO_ROOT")
			if repoRoot == "" {
				repoRoot = "."
			}
			absRepo, _ := filepath.Abs(repoRoot)
			// Handle both absolute paths (from gosec/bandit) and relative (from kics)
			var absFile string
			var ferr error
			if filepath.IsAbs(path) {
				// Path is already absolute — use as-is, but verify it's within repo or allowed
				absFile, ferr = filepath.Abs(path)
			} else {
				// Relative path — join with repo root
				absFile, ferr = filepath.Abs(filepath.Join(absRepo, path))
			}
			var beforeLines, currLines, afterLines []string
			// Security: resolved path must be INSIDE absRepo (or /tmp/).
			//
			// L6-C 2026-05-09: gosec G703 caught a HasPrefix bug here.
			// HasPrefix("/repo-other/secret", "/repo") returns true if
			// absRepo lacks a trailing separator — a tenant who can plant
			// a finding with path="../sibling/.." escapes the workspace.
			// Fix: require absRepo to end in os.PathSeparator before the
			// prefix check; or use filepath.Rel and reject paths starting
			// with "..".
			repoBoundary := absRepo
			if !strings.HasSuffix(repoBoundary, string(os.PathSeparator)) {
				repoBoundary += string(os.PathSeparator)
			}
			pathOK := ferr == nil && (absFile == absRepo ||
				strings.HasPrefix(absFile, repoBoundary) ||
				strings.HasPrefix(absFile, "/tmp/"))
			if pathOK {
				if data, rerr := os.ReadFile(absFile); rerr == nil && len(data) < 5*1024*1024 {
					lines := strings.Split(string(data), "\n")
					if lineNum > 0 && lineNum <= len(lines) {
						bStart := lineNum - 6
						if bStart < 0 {
							bStart = 0
						}
						aEnd := lineNum + 5
						if aEnd > len(lines) {
							aEnd = len(lines)
						}
						beforeLines = lines[bStart : lineNum-1]
						currLines = []string{lines[lineNum-1]}
						resp.LineEnd = lineNum
						if aEnd > lineNum {
							afterLines = lines[lineNum:aEnd]
						}
					}
				}
			}
			resp.ContextBefore = beforeLines
			resp.CurrentCode = currLines
			resp.ContextAfter = afterLines

			// === H3.N LLM integration ===
			if llmProvider != nil && llmPolicy != nil && llmPolicy.AllowLLM(ruleID) && len(currLines) > 0 {
				fixReq := llm.FixRequest{
					RuleID:          ruleID,
					RuleDescription: message,
					FilePath:        path,
					Language:        llm.LanguageFromPath(path),
					Severity:        severity,
					CodeBefore:      strings.Join(beforeLines, "\n"),
					VulnerableCode:  strings.Join(currLines, "\n"),
					CodeAfter:       strings.Join(afterLines, "\n"),
				}
				cacheKey := llm.CacheKey(fixReq)

				// Try cache first
				if cached, cerr := llm.CacheGet(ctx, llmDBAdapter{db.Pool()}, cacheKey); cerr == nil && cached != nil {
					resp.SuggestedFix = strings.Split(cached.SuggestedCode, "\n")
					resp.Rationale = cached.Rationale
					resp.Confidence = cached.Confidence
					resp.BreakingChange = cached.BreakingChange
					resp.HasTemplate = true
					resp.Source = "cache"
					resp.Provider = cached.Provider
					resp.Model = cached.Model
					resp.LatencyMs = cached.LatencyMs
					_ = json.NewEncoder(w).Encode(resp)
					return
				}

				// Cache miss — call LLM with bounded timeout
				// [H3.N.fix8] llm timeout from env
				llmTimeout := 30 * time.Second
				if s := os.Getenv("LLM_TIMEOUT_SECONDS"); s != "" {
					if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 600 {
						llmTimeout = time.Duration(n) * time.Second
					}
				}
				llmCtx, cancel := context.WithTimeout(ctx, llmTimeout)
				defer cancel()
				fixResp, lerr := llmProvider.GenerateFix(llmCtx, fixReq)
				if lerr == nil {
					resp.SuggestedFix = strings.Split(fixResp.SuggestedCode, "\n")
					resp.Rationale = fixResp.Rationale
					resp.Confidence = fixResp.Confidence
					resp.BreakingChange = fixResp.BreakingChange
					resp.HasTemplate = true
					resp.Source = "llm"
					resp.Provider = fixResp.Provider
					resp.Model = fixResp.Model
					resp.LatencyMs = fixResp.LatencyMs
					// Cache (best effort, don't fail request on cache error)
					_ = llm.CacheSet(ctx, llmDBAdapter{db.Pool()}, cacheKey, findingID, fixResp, 0)
					_ = json.NewEncoder(w).Encode(resp)
					return
				}
				// LLM failed — fall through to manual response
				resp.Source = "llm_failed"
				resp.Rationale = "AI fix unavailable (timeout or invalid response). Manual review required."
				_ = json.NewEncoder(w).Encode(resp)
				return
			}

			// Policy blocked or LLM disabled
			if reason := func() string {
				if llmPolicy != nil {
					return llmPolicy.BlockReason(ruleID)
				}
				return ""
			}(); reason != "" {
				resp.Rationale = reason
			} else {
				resp.Rationale = "Manual review required (no auto-fix template, AI generation disabled for this rule)"
			}
			_ = json.NewEncoder(w).Encode(resp)
		})
		// #11 Leaderboard
		r.Get("/api/v1/autofix/leaderboard", func(w http.ResponseWriter, req *http.Request) {
			period := req.URL.Query().Get("period")
			if period == "" {
				period = "30d"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"period": period, "tenant": "default",
				"entries": []any{}, "total": 0,
			})
		})
		// #12 Audit metrics
		r.Get("/api/v1/autofix/metrics", func(w http.ResponseWriter, req *http.Request) {
			period := req.URL.Query().Get("period")
			if period == "" {
				period = "30d"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"period_days": 30, "period": period, "tenant_id": "default",
				"totals": map[string]int{
					"findings_open": 0, "findings_applied": 0, "findings_verified": 0,
					"findings_failed": 0, "findings_accepted": 0, "findings_false_pos": 0,
				},
				"rates": map[string]int{
					"verification_rate": 0, "first_attempt_success": 0, "auto_remediation_rate": 0,
				},
				"mttr": map[string]int{
					"critical_hours": 0, "high_hours": 0, "medium_hours": 0,
					"low_hours": 0, "overall_hours": 0,
				},
				"top_rules_remediated": []any{},
			})
		})
		// ─── End H3.M ────────────────────────────────────────────────────
		// ─── [H3.O] Pre-compute status endpoints ─────────────────────
		r.Get("/api/v1/autofix/precompute/status", handlers.PrecomputeStatusHandler(p4DB))
		r.Get("/api/v1/autofix/precompute/history", handlers.PrecomputeHistoryHandler(p4DB))
		r.Get("/api/v1/autofix/validation/stats", autofix.HandlerValidationStats(p4DB))
		r.Post("/api/v1/autofix/validation/run", autofix.HandlerRunValidation(p4DB))
		r.Get("/api/v1/autofix/validation/{cacheKey}", autofix.HandlerGetValidation(p4DB))
		// ── H3.S Auto-PR endpoints — PRO feature: PR / repo bot ───────
		r.With(requirePro).Post("/api/v1/autofix/pr/create", autopr.HandlerCreatePR(p4DB))
		r.With(requirePro).Get("/api/v1/autofix/pr/list", autopr.HandlerListPR(p4DB))
		r.With(requirePro).Get("/api/v1/autofix/pr/{id}/status", autopr.HandlerPRStatus(p4DB))
		r.With(requirePro).Post("/api/v1/autofix/repo/register", autopr.HandlerRegisterRepo(p4DB))
		r.With(requirePro).Get("/api/v1/autofix/repo/list", autopr.HandlerListRepos(p4DB))
		// Webhook: NOT under auth/PRO middleware (signature-verified instead).
		// Inbound provider webhooks must always succeed regardless of plan;
		// otherwise GitHub/GitLab will retry forever and pollute audit logs.
		r.Post("/api/v1/autofix/pr/webhook/{repoID}", autopr.HandlerWebhook(p4DB))
		// ─── End H3.O ────────────────────────────────────────────────────

		// ─── End H3.O ────────────────────────────────────────────────────

		// ─── End H3.O ────────────────────────────────────────────────────

		// SBOM
		r.Get("/api/v1/sbom/{rid}", sbomH.Generate)
		r.Get("/api/v1/sbom/{rid}/grype", sbomH.Grype)
		r.Get("/api/v1/sbom/{rid}/diff", sbomH.Diff)
		// PHASE3-ROUTES-BEGIN
		// ─── Supply Chain (Sigstore/SLSA/VEX) — Phase 3A — PRO feature
		r.With(requirePro).Get("/api/v1/supply-chain/kpis", supplyChainH.KPIs)
		r.With(requirePro).Get("/api/v1/supply-chain/signatures", supplyChainH.Signatures)
		r.With(requirePro).Get("/api/v1/supply-chain/signatures/{id}", supplyChainH.SignatureDetail)
		r.With(requirePro).Post("/api/v1/supply-chain/signatures/{id}/verify", supplyChainH.Verify)
		r.With(requirePro).Post("/api/v1/supply-chain/sign", supplyChainH.Sign)
		r.With(requirePro).Get("/api/v1/supply-chain/provenance", supplyChainH.Provenance)
		r.With(requirePro).Post("/api/v1/supply-chain/provenance/generate", supplyChainH.GenerateProvenance)
		r.With(requirePro).Get("/api/v1/supply-chain/vex", supplyChainH.VEX)
		// Public keys are non-sensitive verification material — keep open so
		// downstream verifiers can fetch without a paid plan.
		r.Get("/api/v1/supply-chain/key", supplyChainH.Key)
		r.Get("/api/v1/supply-chain/public-key", supplyChainH.Key)
		r.With(requirePro).Post("/api/v1/supply-chain/verify", supplyChainH.VerifyBundle)
		// ─── CISA Secure Software Self-Attestation — Phase 3A ────────
		r.Get("/api/v1/cisa-attestation/kpis", cisaAttestH.KPIs)
		r.Get("/api/v1/cisa-attestation/practices", cisaAttestH.Practices)
		r.Post("/api/v1/cisa-attestation/practices/{id}", cisaAttestH.UpdatePractice)
		r.Put("/api/v1/cisa-attestation/practices/{id}", cisaAttestH.UpdatePractice)
		r.Get("/api/v1/cisa-attestation/forms", cisaAttestH.Forms)
		r.Post("/api/v1/cisa-attestation/forms", cisaAttestH.GenerateDraft)
		r.Get("/api/v1/cisa-attestation/forms/{uuid}", cisaAttestH.FormDetail)
		r.Post("/api/v1/cisa-attestation/forms/{uuid}/sign", cisaAttestH.SignForm)
		r.Get("/api/v1/cisa-attestation/draft", cisaAttestH.CurrentDraft)
		// PHASE3-ROUTES-END
		// PHASE3F-ROUTES-BEGIN
		r.Get("/api/v1/oscal/package", oscalPackageH.BuildPackage)
		// PHASE3F-ROUTES-END
		// PHASE3G-ROUTES-BEGIN
		r.Get("/api/p4/oscal/ap", oscalModelsH.AssessmentPlan)
		r.Get("/api/p4/oscal/ar", oscalModelsH.AssessmentResults)
		r.Get("/api/p4/oscal/poam", oscalModelsH.POAM)
		// PHASE3G-ROUTES-END
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

		// POST /api/v1/remediation/auto-resolve — close remediations whose finding is gone
		r.Post("/api/v1/remediation/auto-resolve", remediationH.AutoResolve)

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
		// PRO gating — PDF rendering uses headless Chromium (~2s CPU + 200MB
		// memory) per call; gate it so free tier can't DoS the runner.
		r.With(requirePro).Get("/api/v1/vsp/executive_report_pdf/{rid}", reportH.ExecutivePDF)
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
		// PRO gating — large exports are bandwidth + DB-IO heavy. SARIF stays
		// free for IDE extensions (small payloads); CSV/full export is gated.
		r.Get("/api/v1/export/sarif/{rid}", exportH.SARIF)
		r.With(requirePro).Get("/api/v1/export/csv/{rid}", exportH.CSV)
		r.Get("/api/v1/export/json/{rid}", exportH.JSON)

		// Software Inventory routes (read-only — under CSRF group)
		swH := &handler.SoftwareInventoryHandler{DB: db}
		r.Get("/api/v1/software-inventory/stats", swH.GetStats)
		r.Get("/api/v1/software-inventory/eol-database", swH.ListEOL)
		r.Get("/api/v1/software-inventory/{hostname}", swH.GetAsset)
		r.Get("/api/v1/software-inventory", swH.ListAssets)
	})

	// ─── [H3.U-1] SW Risk Agent ingest — JWT auth, NO CSRF ──────────
	// Agent gửi report bằng API token thuần (không phải browser),
	// nên cần exempt CSRF middleware. Vẫn yêu cầu authMw.
	r.Group(func(r chi.Router) {
		r.Use(authMw)
		swIngestH := &handler.SoftwareInventoryHandler{DB: db}
		r.Post("/api/v1/software-inventory/report", swIngestH.ReceiveReport)
	})

	addr := fmt.Sprintf(":%d", viper.GetInt("server.gateway_port"))
	// ─── [H3.T] Agentic routes (auth-protected) ──────────────────────
	r.Group(func(r chi.Router) {
		r.Use(authMw)
		agenticHandlers.RegisterRoutes(r)
	})

	// VSP PRO — Container scanner (Trivy) — P0 backend.
	// PRO feature: gated by authMw + requirePro so starter tenants
	// can't trigger expensive Trivy scans. Routes: /api/v1/container/{images,scan,scan/{id},seed}.
	containerScanner := container.NewScanner()
	container.NewAPI(containerScanner).RegisterRoutes(r, authMw, requirePro)
	log.Info().Msg("container: Trivy scanner API initialized (PRO-gated) — POST /api/v1/container/seed to start")

	// ─── Microservice reverse proxies ───────────────────────────────────────
	// Frontend panels in static/index.html are configured to hit these prefixes
	// (window.VSP_COSIGN_API='/api/sc', etc.) so the gateway must transparently
	// forward to the corresponding microservice. The microservices live on
	// 8091-8095 as their own systemd units; the prefix is stripped before
	// forwarding so /api/sc/healthz → http://127.0.0.1:8091/healthz.
	mountMicroProxy := func(prefix, target string) {
		u, err := url.Parse(target)
		if err != nil {
			log.Fatal().Err(err).Str("target", target).Msg("invalid microservice proxy target")
		}
		proxy := httputil.NewSingleHostReverseProxy(u)
		// Swallow microservice-down errors with a short JSON 502 instead of
		// the default plaintext "EOF" so frontend panels can render a clean
		// error state.
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"microservice unreachable","upstream":"` + target + `"}`))
		}
		r.Mount(prefix, http.StripPrefix(prefix, proxy))
		log.Info().Str("prefix", prefix).Str("target", target).Msg("microservice proxy mounted")
	}
	mountMicroProxy("/api/sc", "http://127.0.0.1:8091")    // cosign-api
	mountMicroProxy("/api/sched", "http://127.0.0.1:8092") // scheduler-api
	mountMicroProxy("/api/dast", "http://127.0.0.1:8093")  // dast-api
	mountMicroProxy("/api/swinv", "http://127.0.0.1:8094") // sw-inventory
	mountMicroProxy("/api/email", "http://127.0.0.1:8095") // email-api

	// L17.18.3 slowloris mitigation: bound every phase of the request
	// lifecycle so a slow client can't tie up a goroutine indefinitely.
	//   ReadHeaderTimeout — caps the HTTP header read (slow-header attack)
	//   ReadTimeout       — caps header + body together (slow-body attack)
	//   IdleTimeout       — caps keep-alive idle between requests
	//   WriteTimeout=0    — keep streaming responses (SSE, long polls) unbounded
	srv := &http.Server{Addr: addr, Handler: r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		WriteTimeout:      0,
	}

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

	// G38: POAM auto-gen worker (every 5 min)
	go poam.New(p4DB, 5*time.Minute).Start(ctx)
	log.Info().Msg("poam: auto-gen worker scheduled")

	// Notification fan-out worker — drains notification_log entries written
	// by every PRO panel (CSPM finding alerts, supply-chain admission denial,
	// etc.) and POSTs them to the per-tenant Slack/Teams/generic webhook
	// configured in the Notifications panel. Tick = 5 s.
	// Notification fan-out worker. Webhook body signing pulls the HMAC
	// secret from the configured secrets provider — empty string when
	// not configured, in which case signatures are simply not added
	// (backward compatible).
	whSign := ""
	if sp, sErr := secrets.Default(); sErr == nil {
		if v, err := sp.Get("webhook_signing"); err == nil {
			whSign = v
		}
	}
	go notify.NewFanout(db.Pool(), 5*time.Second).WithSigningKey(whSign).Run(ctx)
	// Erasure worker: scans every 5 min for confirmed DSR-erasure requests
	// whose grace window has elapsed, and runs the cascading deletion.
	go handler.RunErasureWorker(ctx, db, 5*time.Minute)

	// KPI watchdog (Sprint 8.7) — re-runs the kpi/sanity invariants
	// every 5 min and writes KPI_SANITY_FAILED to audit_log on regression.
	go handler.RunKPIWatchdog(ctx, db, 5*time.Minute)
	log.Info().Msg("notification fan-out worker scheduled")

	log.Info().Msg("Incident email alerter started — interval: 30s")

	// ── Retention policy worker ──────────────────────────────────
	safe.GoCtx(ctx, func(ctx context.Context) { siem.StartRetentionWorker(ctx, db) })

	// ── SOAR zombie run cleanup ──────────────────────────────────
	soarZombie := soar.NewZombieRecovery(db, 10*time.Minute)
	safe.GoCtx(ctx, func(ctx context.Context) { soarZombie.StartLoop(ctx, 5*time.Minute) })
	log.Info().Msg("SOAR zombie cleanup worker started")

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

// splitCSV is a tolerant comma-separated splitter (handles spaces).
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// trustedRealIP returns a middleware that rewrites r.RemoteAddr from
// X-Forwarded-For / X-Real-IP ONLY when the immediate TCP source is
// in the trusted-proxy allow-list. For any other source, the headers
// are stripped so they can't influence downstream IP gates.
//
// trustedCIDRs is a comma-separated list of CIDRs (e.g.
// "10.0.0.0/8,172.16.0.0/12"). Empty defaults to loopback only.
func trustedRealIP(trustedCIDRs string) func(http.Handler) http.Handler {
	defaults := []string{"127.0.0.0/8", "::1/128"}
	var nets []*net.IPNet
	for _, c := range append(defaults, splitCSV(trustedCIDRs)...) {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			nets = append(nets, n)
		}
	}
	isTrusted := func(addr string) bool {
		host := addr
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if ip == nil {
			return false
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isTrusted(r.RemoteAddr) {
				// Source isn't a trusted proxy — discard any forwarding
				// headers an attacker may have set so chi.RealIP (or
				// downstream code) can't be tricked.
				r.Header.Del("X-Forwarded-For")
				r.Header.Del("X-Real-IP")
				r.Header.Del("X-Forwarded-Host")
				r.Header.Del("X-Forwarded-Proto")
			}
			chimw.RealIP(next).ServeHTTP(w, r)
		})
	}
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
		// Touch in a fresh ctx — the request ctx gets cancelled the
		// moment the response flushes, and pgx then drops the UPDATE
		// with "context canceled", so the api_keys.last_used_at column
		// stays NULL forever. Same fix as the password / siem.Deliver /
		// audit-log goroutines.
		keyID := id
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.db.TouchAPIKey(bgCtx, keyID)
		}()
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
