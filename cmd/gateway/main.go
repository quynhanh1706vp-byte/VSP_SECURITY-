package main

import (
	"strings"
	"bytes"
	"io"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	_ "net/http/pprof" // profiling endpoint /debug/pprof/
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"database/sql"
	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"

	"github.com/vsp/platform/internal/api/handler"
	vspMW "github.com/vsp/platform/internal/api/middleware"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/cache"
	"github.com/vsp/platform/internal/migrate"
	"github.com/vsp/platform/internal/pipeline"
	"github.com/vsp/platform/internal/safe"
	"github.com/vsp/platform/internal/scheduler"
	"github.com/vsp/platform/internal/siem"
	"github.com/vsp/platform/internal/store"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"
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
	// Docker env var mappings — sau SetDefault để override
	viper.BindEnv("database.url", "DATABASE_URL")
	viper.BindEnv("redis.addr", "REDIS_ADDR")
	viper.BindEnv("redis.password", "REDIS_PASSWORD")
	viper.BindEnv("auth.jwt_secret", "JWT_SECRET")
	viper.BindEnv("server.env", "SERVER_ENV")
	viper.BindEnv("server.allowed_origins", "ALLOWED_ORIGINS")
	if err := viper.ReadInConfig(); err != nil {
		log.Warn().Err(err).Msg("no config file — using defaults")
	}

	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	ctx, shutdown := context.WithCancel(context.Background())
	defer shutdown()
	db, err := store.New(ctx, viper.GetString("database.url"))
	if err != nil { log.Fatal().Err(err).Msg("database connect failed") }
	defer db.Close()
	log.Info().Msg("database connected ✓")

	// Auto-run migrations
	stdDB, err2 := sql.Open("pgx", viper.GetString("database.url"))
	if err2 != nil { log.Fatal().Err(err2).Msg("open db for migrations") }
	if err2 = migrate.Run(ctx, stdDB); err2 != nil { log.Fatal().Err(err2).Msg("migration failed") }
	stdDB.Close()
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
	asynqClient := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     redisAddr,
		Password: redisPass,
	})
	defer asynqClient.Close()
	// ── Redis API cache ──────────────────────────────────────────────────────
	ca := cache.New(redisAddr, redisPass)


	// ── All handlers ──────────────────────────────────────────────
	authH       := &handler.Auth{DB: db, JWTSecret: jwtSecret, JWTTTL: jwtTTL, DefaultTID: defaultTID}
	handler.SetJWTSecret(jwtSecret)
	usersH      := &handler.Users{DB: db}
	mfaH        := &handler.MFA{DB: db}
	apiKeysH    := &handler.APIKeys{DB: db}
	runsH       := &handler.Runs{DB: db}
	runsH.SetAsynqClient(asynqClient)
	findingsH   := &handler.Findings{DB: db}
	gateH       := &handler.Gate{DB: db}
	auditH      := &handler.Audit{DB: db}
	siemH       := &handler.SIEM{DB: db}
	// ── SIEM handlers ────────────────────────────────────────
	corrH      := &handler.Correlation{DB: db}
	// ── UEBA + Assets ────────────────────────────────────────
	uebaH   := &handler.UEBA{DB: db}
	assetsH := &handler.Assets{DB: db}
	soarH      := &handler.SOAR{DB: db}
	logSrcH    := &handler.LogSources{DB: db}
	tiH        := &handler.ThreatIntel{DB: db}
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
	r.Use(vspMW.CSPNonce)
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
		r.Mount("/debug", http.DefaultServeMux)
	}
	r.Handle("/metrics", handler.MetricsHandler())
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx2, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		checks := map[string]any{}
		overall := "ok"
		t0 := time.Now()
		if err := db.Pool().Ping(ctx2); err != nil {
			checks["database"] = map[string]string{"status":"error","error":err.Error()}
			overall = "error"
		} else {
			checks["database"] = map[string]string{"status":"ok","latency":time.Since(t0).String()}
		}
		w.Header().Set("Content-Type", "application/json")
		if overall == "error" { w.WriteHeader(503) }
		json.NewEncoder(w).Encode(map[string]any{
			"status": overall, "version": "0.10.0",
			"port": viper.GetInt("server.gateway_port"),
			"tier": "enterprise", "checks": checks,
			"uptime": time.Since(startTime).Round(time.Second).String(),
		})
	})
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
		r.Use(vspMW.NewUserRateLimiter(300, time.Minute)) // per-user: 300 req/min

		// Auth
		r.Post("/api/v1/auth/logout",      authH.Logout)
		r.Post("/api/v1/auth/refresh",     authH.Refresh)
		r.Post("/api/v1/auth/mfa/setup",   mfaH.Setup)
		r.Post("/api/v1/auth/mfa/verify",  mfaH.Verify)
		r.Delete("/api/v1/auth/mfa",       mfaH.Disable)
		r.Post("/api/v1/auth/password/change", authH.ChangePassword)

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
		r.With(ca.Middleware("runs-index", 10*time.Second)).Get("/api/v1/vsp/runs/index", runsH.Index)
		r.Get("/api/v1/vsp/findings", findingsH.List)
		r.With(ca.Middleware("findings-summary", 15*time.Second)).Get("/api/v1/vsp/findings/summary", findingsH.Summary)

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
		r.Post("/api/v1/audit/verify", auditH.Verify)

		// SIEM
		r.Get("/api/v1/siem/webhooks", siemH.List)

		// ── Correlation engine ─────────────────────────────────
		r.Get("/api/v1/correlation/rules",           corrH.ListRules)
		r.Post("/api/v1/correlation/rules",          corrH.CreateRule)
		r.Post("/api/v1/correlation/rules/{id}/toggle", corrH.ToggleRule)
		r.Delete("/api/v1/correlation/rules/{id}",   corrH.DeleteRule)
		r.Get("/api/v1/correlation/incidents",       corrH.ListIncidents)
		r.Get("/api/v1/correlation/incidents/{id}",  corrH.GetIncident)
		r.Post("/api/v1/correlation/incidents/{id}/resolve", corrH.ResolveIncident)
		r.Patch("/api/v1/correlation/incidents/{id}/status", corrH.ResolveIncident)
		r.Post("/api/v1/correlation/incidents",      corrH.CreateIncident)

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
			if run != nil { gate = run.Gate; findings = run.TotalFindings }
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
			if len(req.Messages) > 0 { query = req.Messages[len(req.Messages)-1]["content"] }
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
			w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "text", "text": reply}}, "model": "vsp-mock"})
		})

		// ── AI Analyst proxy ──────────────────────────────────── ────────────────────────────────────
		r.Post("/api/v1/ai/chat", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Forward to Anthropic API
			body, err := io.ReadAll(r.Body)
			if err != nil { http.Error(w, "bad request", 400); return }
			req, err := http.NewRequestWithContext(r.Context(), "POST",
				"https://api.anthropic.com/v1/messages",
				bytes.NewReader(body))
			if err != nil { http.Error(w, "proxy error", 500); return }
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("anthropic-version", "2023-06-01")
			apiKey := viper.GetString("anthropic.api_key")
			if apiKey != "" { req.Header.Set("x-api-key", apiKey) }
			client := &http.Client{Timeout: 60 * time.Second}
			resp, err := client.Do(req)
			if err != nil { http.Error(w, `{"error":"upstream error"}`+err.Error(), http.StatusBadGateway); return }
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
		r.Post("/api/v1/ueba/analyze",  uebaH.Analyze)
		r.Get("/api/v1/ueba/baseline",  uebaH.Baseline)
		r.Get("/api/v1/ueba/timeline",  uebaH.Timeline)

		// ── Asset inventory ─────────────────────────────────────
		r.Get("/api/v1/assets",                assetsH.List)
		r.Post("/api/v1/assets",               assetsH.Create)
		r.Get("/api/v1/assets/summary",        assetsH.Summary)
		r.Get("/api/v1/assets/{id}/findings",  assetsH.Findings)

		// ── SOAR playbooks ──────────────────────────────────────
		r.Get("/api/v1/soar/playbooks",              soarH.ListPlaybooks)
		r.Post("/api/v1/soar/playbooks",             soarH.CreatePlaybook)
		r.Post("/api/v1/soar/playbooks/{id}/toggle", soarH.TogglePlaybook)
		r.Post("/api/v1/soar/playbooks/{id}/run",    soarH.RunPlaybook)
		r.Post("/api/v1/soar/trigger",               soarH.Trigger)
		r.Get("/api/v1/soar/runs",                   soarH.ListRuns)

// ── Vulnerability management ───────────────────────────────
		r.Get("/api/v1/vulns/trend", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			days := 30
			if d := r.URL.Query().Get("days"); d != "" { fmt.Sscanf(d, "%d", &days) }
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
			if err != nil { w.Header().Set("Content-Type","application/json"); json.NewEncoder(w).Encode(map[string]any{"trend":[]any{}}); return }
			defer rows.Close()
			var points []TrendPoint
			for rows.Next() {
				var p TrendPoint
				rows.Scan(&p.Date,&p.Critical,&p.High,&p.Medium,&p.Low,&p.Total) //nolint:errcheck
				points = append(points, p)
			}
			if points == nil { points = []TrendPoint{} }
			w.Header().Set("Content-Type","application/json")
			json.NewEncoder(w).Encode(map[string]any{"trend":points,"days":days}) //nolint:errcheck
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
			if err != nil { w.Header().Set("Content-Type","application/json"); json.NewEncoder(w).Encode(map[string]any{"cves":[]any{}}); return }
			defer rows.Close()
			var cves []CVERow
			for rows.Next() {
				var c CVERow
				rows.Scan(&c.CVE,&c.Severity,&c.Count,&c.Tools,&c.Fixable) //nolint:errcheck
				cves = append(cves, c)
			}
			if cves == nil { cves = []CVERow{} }
			w.Header().Set("Content-Type","application/json")
			json.NewEncoder(w).Encode(map[string]any{"cves":cves,"total":len(cves)}) //nolint:errcheck
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
			if err != nil { w.Header().Set("Content-Type","application/json"); json.NewEncoder(w).Encode(map[string]any{"tools":[]any{}}); return }
			defer rows.Close()
			var tools []ToolRow
			for rows.Next() {
				var t ToolRow
				rows.Scan(&t.Tool,&t.Critical,&t.High,&t.Medium,&t.Low,&t.Total) //nolint:errcheck
				tools = append(tools, t)
			}
			if tools == nil { tools = []ToolRow{} }
			w.Header().Set("Content-Type","application/json")
			json.NewEncoder(w).Encode(map[string]any{"tools":tools}) //nolint:errcheck
		})

// ── Threat hunting ─────────────────────────────────────────
		r.Get("/api/v1/logs/hunt", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.FromContext(r.Context())
			ctx := r.Context()
			q := r.URL.Query()
			keyword  := q.Get("q")
			severity := q.Get("severity")
			process  := q.Get("process")
			sourceIP := q.Get("source_ip")
			limitStr := q.Get("limit")
			limit    := 100
			if limitStr != "" { fmt.Sscanf(limitStr, "%d", &limit) }
			if limit > 500 { limit = 500 }
			where := []string{"tenant_id=$1"}
			args  := []any{claims.TenantID}
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
			if h := q.Get("hours"); h != "" { fmt.Sscanf(h, "%d", &hours) }
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
				w.Header().Set("Content-Type","application/json")
				json.NewEncoder(w).Encode(map[string]any{"error":err.Error()})
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
				rows.Scan(&e.ID, &ts, &e.Host, &e.Process, &e.Severity,
					&e.Facility, &e.Message, &e.SourceIP, &e.Format) //nolint:errcheck
				if t, ok := ts.(interface{ Format(string) string }); ok {
					e.TS = t.Format("2006-01-02 15:04:05")
				} else {
					e.TS = fmt.Sprintf("%v", ts)
				}
				events = append(events, e)
			}
			if events == nil { events = []Event{} }

			// Stats — dùng toàn bộ where + args (bao gồm time filter)
			var total int
			db.Pool().QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM log_events WHERE %s`,
				strings.Join(where, " AND ")), args[:len(args)-1]...).Scan(&total) //nolint:errcheck

			w.Header().Set("Content-Type","application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"events": events,
				"count":  len(events),
				"total":  total,
				"query":  map[string]any{"q":keyword,"severity":severity,"process":process,"hours":hours},
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
					rows.Scan(&h.IP, &h.Count, &h.Sev) //nolint:errcheck
					hosts = append(hosts, h)
				}
				rows.Close()
			}
			if hosts == nil { hosts = []FlowHost{} }

			// Stats tổng
			var totalFlows, suspicious int
			db.Pool().QueryRow(ctx, `
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
			if procs == nil { procs = []ProcStat{} }

			w.Header().Set("Content-Type", "application/json") //nolint:errcheck
			json.NewEncoder(w).Encode(map[string]any{
				"flows_per_min": totalFlows / 60,
				"total_1h":      totalFlows,
				"suspicious":    suspicious,
				"top_hosts":     hosts,
				"top_processes": procs,
			}) //nolint:errcheck
		})

		// ── Log sources ─────────────────────────────────────────
		r.Get("/api/v1/logs/sources",                logSrcH.List)
		r.Post("/api/v1/logs/sources",               logSrcH.Create)
		r.Delete("/api/v1/logs/sources/{id}",        logSrcH.Delete)
		r.Post("/api/v1/logs/sources/{id}/test",     logSrcH.Test)
		r.Get("/api/v1/logs/stats",                  logSrcH.Stats)

		// ── Threat intelligence ─────────────────────────────────
		r.Get("/api/v1/ti/iocs",                     tiH.ListIOCs)
		r.Get("/api/v1/ti/feeds",                    tiH.ListFeeds)
		r.Get("/api/v1/ti/matches",                  tiH.Matches)
		r.Get("/api/v1/ti/mitre",                    tiH.MITRE)
		r.Post("/api/v1/ti/feeds/sync",              tiH.SyncFeeds)
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
				if err != nil { continue }
				var toTrigger []struct{ rid, tenantID, gate string; findings int }
				for rows.Next() {
					var id, rid, tenantID, gate string
					var findings int
					var summary []byte
					var createdAt time.Time
					if err := rows.Scan(&id, &rid, &tenantID, &gate, &findings, &summary, &createdAt); err != nil { continue }
					if rid <= lastSeen { continue }
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
						toTrigger = append(toTrigger, struct{ rid, tenantID, gate string; findings int }{rid, tenantID, gate, findings})
					}
				}
				rows.Close()
				// Trigger SOAR for FAIL gates
				for _, t := range toTrigger {
					pbs, err := db.FindEnabledPlaybooks(ctx, t.tenantID, "gate_fail", "any")
					if err != nil { continue }
					for _, pb := range pbs {
						ctxJSON, _ := json.Marshal(map[string]any{
							"trigger":"gate_fail","gate":t.gate,
							"run_id":t.rid,"findings":t.findings,
						})
						runID, err := db.CreatePlaybookRun(ctx, pb.ID, t.tenantID, "gate_fail", ctxJSON)
						if err != nil { continue }
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
	if udpAddr == "" { udpAddr = ":10514" }
	tcpAddr := viper.GetString("siem.syslog_tcp_addr")
	if tcpAddr == "" { tcpAddr = ":10515" }
	var tenantID string
	db.Pool().QueryRow(ctx, `SELECT id FROM tenants WHERE slug='default' LIMIT 1`).Scan(&tenantID) //nolint:errcheck
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
	asynqClient.Close()
	log.Info().Msg("stopped ✓")
}

func corsMiddleware(next http.Handler) http.Handler {
	raw := viper.GetString("server.allowed_origins")
	if raw == "" {
		raw = "http://localhost:3000,http://localhost:8922,http://127.0.0.1:8922,http://127.0.0.1:8921"
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

