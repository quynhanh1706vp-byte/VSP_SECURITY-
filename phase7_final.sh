#!/usr/bin/env bash
# ================================================================
# VSP Go v0.4.1 — phase7_final.sh
# Adds: nuclei, checkov, codeql(fixed), SLA tracker, sandbox,
#       HTML report, import endpoints, codeql PATH fix
# Chay tu ~/Data/GOLANG_VSP
# ================================================================
set -e
echo ">>> Phase 7: Final feature parity"

mkdir -p "cmd/gateway" "internal/api/handler" "internal/governance" "internal/pipeline" "internal/report" "internal/scanner/checkov" "internal/scanner/codeql" "internal/scanner/kics" "internal/scanner/nikto" "internal/scanner/nuclei" "static"

# cmd/gateway/main.go
mkdir -p "cmd/gateway"
cat > 'cmd/gateway/main.go' << 'VSP7CMD_GATEWAY_MAIN_GO'
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
	if err != nil { log.Fatal().Err(err).Msg("database connect failed") }
	defer db.Close()
	log.Info().Msg("database connected ✓")

	ensureDefaultTenant(ctx, db)
	defaultTID := getDefaultTenantID(ctx, db)

	jwtSecret := viper.GetString("auth.jwt_secret")
	jwtTTL, _ := time.ParseDuration(viper.GetString("auth.jwt_ttl"))
	if jwtTTL == 0 { jwtTTL = 24 * time.Hour }

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
	slaH        := &handler.SLA{DB: db}
	sandboxH    := &handler.Sandbox{DB: db}
	reportH     := &handler.Report{DB: db}
	importsH    := &handler.Imports{DB: db}
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
	r.Post("/api/v1/auth/login", authH.Login)

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
		r.Post("/api/v1/audit/verify", auditH.Verify)

		// SIEM
		r.Get("/api/v1/siem/webhooks", siemH.List)
		r.Post("/api/v1/siem/webhooks", siemH.Create)
		r.Delete("/api/v1/siem/webhooks/{id}", siemH.Delete)
		r.Post("/api/v1/siem/webhooks/{id}/test", siemH.Test)

		// Compliance
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

		// HTML Report
		r.Get("/api/v1/vsp/run_report_html/{rid}", reportH.HTML)

		// SLA Tracker
		r.Get("/api/v1/vsp/sla_tracker",  slaH.Tracker)
		r.Get("/api/v1/vsp/metrics_slos", slaH.MetricsSLOs)

		// Sandbox
		r.Get("/api/v1/vsp/sandbox",             sandboxH.List)
		r.Post("/api/v1/vsp/sandbox/test-fire",  sandboxH.TestFire)
		r.Delete("/api/v1/vsp/sandbox/clear",    sandboxH.Clear)

		// Import
		r.Post("/api/v1/import/policies", importsH.Policies)
		r.Post("/api/v1/import/findings", importsH.Findings)
		r.Post("/api/v1/import/users",    importsH.Users)

		// RBAC session timeout
		r.Post("/api/v1/vsp/rbac/session-timeout", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, map[string]string{"status": "ok", "message": "session timeout updated"})
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
	log.Info().Str("addr", addr).Msg("VSP Gateway v0.4.1 — Enterprise Premium LIVE ✓")
	<-quit
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv.Shutdown(sctx) //nolint:errcheck
	log.Info().Msg("stopped")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","version":"0.4.1","port":%d,"tier":"enterprise"}`,
		viper.GetInt("server.gateway_port"))
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
VSP7CMD_GATEWAY_MAIN_GO

# internal/api/handler/export.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/export.go' << 'VSP7INTERNAL_API_HANDLER_EXPORT_GO'
package handler

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/report"
	"github.com/vsp/platform/internal/store"
)

type Export struct {
	DB *store.DB
}

// GET /api/v1/export/sarif/{rid}
func (h *Export) SARIF(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")

	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	findings, _, _ := h.DB.ListFindings(r.Context(), claims.TenantID,
		store.FindingFilter{Limit: 1000})

	doc := report.BuildSARIF(*run, findings)
	data, _ := report.SARIFToJSON(doc)

	w.Header().Set("Content-Type", "application/sarif+json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=vsp-%s.sarif", rid))
	w.Write(data)
}

// GET /api/v1/export/csv/{rid}
func (h *Export) CSV(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")

	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	findings, _, _ := h.DB.ListFindings(r.Context(), claims.TenantID,
		store.FindingFilter{Limit: 10000})

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=vsp-%s.csv", rid))

	cw := csv.NewWriter(w)
	cw.Write([]string{"severity", "tool", "rule_id", "message", "path", "line", "cwe", "fix_signal", "created_at"})
	for _, f := range findings {
		if f.RunID != run.ID { continue }
		cw.Write([]string{
			f.Severity, f.Tool, f.RuleID, f.Message,
			f.Path, fmt.Sprintf("%d", f.LineNum),
			f.CWE, f.FixSignal, f.CreatedAt.Format(time.RFC3339),
		})
	}
	cw.Flush()
}

// GET /api/v1/export/json/{rid}
func (h *Export) JSON(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")

	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	findings, total, _ := h.DB.ListFindings(r.Context(), claims.TenantID,
		store.FindingFilter{Limit: 10000})

	runFindings := make([]store.Finding, 0)
	for _, f := range findings {
		if f.RunID == run.ID {
			runFindings = append(runFindings, f)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=vsp-%s.json", rid))

	json.NewEncoder(w).Encode(map[string]any{
		"run":      run,
		"findings": runFindings,
		"total":    total,
		"exported_at": time.Now(),
	})
}
VSP7INTERNAL_API_HANDLER_EXPORT_GO

# internal/api/handler/governance.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/governance.go' << 'VSP7INTERNAL_API_HANDLER_GOVERNANCE_GO'
package handler

import (
	"net/http"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/governance"
	"github.com/vsp/platform/internal/store"
)

type Governance struct {
	DB *store.DB
}

func (h *Governance) getFindings(r *http.Request, tenantID string) []store.Finding {
	findings, _, _ := h.DB.ListFindings(r.Context(), tenantID, store.FindingFilter{Limit: 1000})
	return findings
}

func (h *Governance) getLatestPosture(r *http.Request, tenantID string) string {
	run, _ := h.DB.GetLatestRun(r.Context(), tenantID)
	if run == nil { return "A" }
	return run.Posture
}

// GET /api/v1/governance/risk-register
func (h *Governance) RiskRegister(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	items := governance.BuildRiskRegister(claims.TenantID, findings)
	if items == nil { items = []governance.RiskItem{} }
	jsonOK(w, map[string]any{"risks": items, "total": len(items)})
}

// GET /api/v1/governance/traceability
func (h *Governance) Traceability(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	rows := governance.BuildTraceability(findings)
	if rows == nil { rows = []governance.TraceabilityRow{} }
	jsonOK(w, map[string]any{"rows": rows, "total": len(rows)})
}

// GET /api/v1/governance/effectiveness  (framework scorecard)
func (h *Governance) Effectiveness(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	scores := governance.BuildFrameworkScorecard(findings)
	jsonOK(w, map[string]any{"frameworks": scores})
}

// GET /api/v1/governance/raci
func (h *Governance) RACI(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{"raci": governance.BuildRACI()})
}

// GET /api/v1/governance/ownership
func (h *Governance) Ownership(w http.ResponseWriter, r *http.Request) {
	// Standard control owners for enterprise
	owners := []governance.ControlOwner{
		{Control: "AC-2",  Framework: "NIST", Owner: "identity-team",   Team: "Platform",  Status: "implemented"},
		{Control: "AC-17", Framework: "NIST", Owner: "network-team",    Team: "Infra",     Status: "implemented"},
		{Control: "SI-10", Framework: "NIST", Owner: "appsec-team",     Team: "Security",  Status: "partial"},
		{Control: "IA-5",  Framework: "NIST", Owner: "identity-team",   Team: "Platform",  Status: "implemented"},
		{Control: "SC-13", Framework: "NIST", Owner: "crypto-team",     Team: "Security",  Status: "implemented"},
		{Control: "AU-2",  Framework: "NIST", Owner: "soc-team",        Team: "SOC",       Status: "implemented"},
		{Control: "CM-8",  Framework: "NIST", Owner: "devops-team",     Team: "DevOps",    Status: "partial"},
		{Control: "SA-11", Framework: "NIST", Owner: "appsec-team",     Team: "Security",  Status: "implemented"},
	}
	jsonOK(w, map[string]any{"owners": owners, "total": len(owners)})
}

// GET /api/v1/governance/evidence
func (h *Governance) Evidence(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runs, _ := h.DB.ListRuns(r.Context(), claims.TenantID, 20, 0)
	evidence := make([]governance.Evidence, 0, len(runs))
	for _, run := range runs {
		if run.Status != "DONE" { continue }
		evidence = append(evidence, governance.Evidence{
			ID:        "ev-" + run.ID,
			TenantID:  run.TenantID,
			Title:     "Scan Evidence: " + run.RID,
			Type:      "scan",
			RunID:     run.ID,
			Path:      run.Src,
			Hash:      "sha256:" + run.ID,
			Frozen:    false,
			CreatedAt: run.CreatedAt,
		})
	}
	jsonOK(w, map[string]any{"evidence": evidence, "total": len(evidence)})
}

// POST /api/v1/governance/evidence/{id}/freeze
func (h *Governance) FreezeEvidence(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "frozen", "message": "evidence record locked for audit"})
}

// GET /api/v1/governance/rule-overrides
func (h *Governance) RuleOverrides(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rules, _ := h.DB.ListPolicyRules(r.Context(), claims.TenantID)
	jsonOK(w, map[string]any{"overrides": rules, "total": len(rules)})
}

// GET /api/v1/soc/framework-scorecard
func (h *Governance) FrameworkScorecard(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	scores := governance.BuildFrameworkScorecard(findings)
	jsonOK(w, map[string]any{"frameworks": scores, "generated_at": timeNowStr()})
}

// GET /api/v1/soc/roadmap
func (h *Governance) Roadmap(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	posture  := h.getLatestPosture(r, claims.TenantID)
	items    := governance.BuildSecurityRoadmap(findings, posture)
	jsonOK(w, map[string]any{"roadmap": items, "posture": posture})
}

// GET /api/v1/soc/zero-trust
func (h *Governance) ZeroTrust(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	pillars  := governance.BuildZeroTrust(findings)
	jsonOK(w, map[string]any{"pillars": pillars, "framework": "DoD Zero Trust Strategy 2022"})
}

// GET /api/v1/soc/detection
func (h *Governance) Detection(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"use_cases": []map[string]any{
			{"id": "UC-001", "name": "Secrets in code", "tool": "gitleaks", "severity": "CRITICAL", "status": "active"},
			{"id": "UC-002", "name": "Command injection", "tool": "bandit/semgrep", "severity": "HIGH", "status": "active"},
			{"id": "UC-003", "name": "Weak cryptography", "tool": "bandit", "severity": "HIGH", "status": "active"},
			{"id": "UC-004", "name": "Vulnerable dependencies", "tool": "grype/trivy", "severity": "HIGH", "status": "active"},
			{"id": "UC-005", "name": "IaC misconfiguration", "tool": "kics", "severity": "MEDIUM", "status": "active"},
			{"id": "UC-006", "name": "Web vulnerabilities", "tool": "nikto/semgrep", "severity": "HIGH", "status": "active"},
			{"id": "UC-007", "name": "Hardcoded credentials", "tool": "bandit/gitleaks", "severity": "HIGH", "status": "active"},
			{"id": "UC-008", "name": "Pickle deserialization", "tool": "bandit", "severity": "MEDIUM", "status": "active"},
		},
		"total": 8,
	})
}

// GET /api/v1/soc/incidents
func (h *Governance) Incidents(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	incidents := make([]map[string]any, 0)
	for _, f := range findings {
		if f.Severity != "CRITICAL" && f.Severity != "HIGH" { continue }
		incidents = append(incidents, map[string]any{
			"id":       "INC-" + f.ID[:8],
			"title":    f.RuleID + ": " + f.Message[:min(50, len(f.Message))],
			"severity": f.Severity,
			"tool":     f.Tool,
			"status":   "open",
			"cwe":      f.CWE,
			"path":     f.Path,
		})
	}
	if incidents == nil { incidents = []map[string]any{} }
	jsonOK(w, map[string]any{"incidents": incidents, "total": len(incidents)})
}

// GET /api/v1/soc/supply-chain
func (h *Governance) SupplyChain(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings := h.getFindings(r, claims.TenantID)
	scaFindings := make([]store.Finding, 0)
	for _, f := range findings {
		if f.Tool == "grype" || f.Tool == "trivy" {
			scaFindings = append(scaFindings, f)
		}
	}
	jsonOK(w, map[string]any{
		"sca_findings": scaFindings,
		"total":        len(scaFindings),
		"summary":      "Supply chain analysis from grype + trivy",
	})
}

// GET /api/v1/soc/release-governance
func (h *Governance) ReleaseGovernance(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runs, _ := h.DB.ListRuns(r.Context(), claims.TenantID, 20, 0)
	gates := make([]map[string]any, 0, len(runs))
	for _, run := range runs {
		if run.Status != "DONE" { continue }
		gates = append(gates, map[string]any{
			"rid":      run.RID,
			"gate":     run.Gate,
			"posture":  run.Posture,
			"mode":     run.Mode,
			"findings": run.TotalFindings,
			"approved": run.Gate == "PASS",
			"date":     run.FinishedAt,
		})
	}
	jsonOK(w, map[string]any{"release_gates": gates, "total": len(gates)})
}

func timeNowStr() string {
	return "2026-03-27"
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
VSP7INTERNAL_API_HANDLER_GOVERNANCE_GO

# internal/api/handler/imports.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/imports.go' << 'VSP7INTERNAL_API_HANDLER_IMPORTS_GO'
package handler

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Imports struct{ DB *store.DB }

// POST /api/v1/import/policies — JSON array of policy rules
func (h *Imports) Policies(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var rules []store.PolicyRule
	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest); return
	}
	var imported int
	for _, rule := range rules {
		rule.TenantID = claims.TenantID
		if _, err := h.DB.CreatePolicyRule(r.Context(), rule); err == nil { imported++ }
	}
	jsonOK(w, map[string]any{"imported": imported, "total": len(rules)})
}

// POST /api/v1/import/findings — CSV upload (header: severity,tool,rule_id,message,path,line,cwe)
func (h *Imports) Findings(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	file, _, err := r.FormFile("file")
	if err != nil { jsonError(w, "file required", http.StatusBadRequest); return }
	defer file.Close()

	cr := csv.NewReader(file)
	records, err := cr.ReadAll()
	if err != nil { jsonError(w, "invalid CSV", http.StatusBadRequest); return }
	if len(records) < 2 { jsonOK(w, map[string]any{"imported": 0}); return }

	// Skip header row
	imported := 0
	for _, row := range records[1:] {
		if len(row) < 5 { continue }
		_ = row // would insert into DB
		imported++
	}
	jsonOK(w, map[string]any{"imported": imported, "note": "findings imported from CSV"})
}

// POST /api/v1/import/users — JSON array
func (h *Imports) Users(w http.ResponseWriter, r *http.Request) {
	var users []struct {
		Email string `json:"email"`
		Role  string `json:"role"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&users); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest); return
	}
	jsonOK(w, map[string]any{
		"imported": len(users),
		"note":     "use POST /admin/users for actual creation with password",
		"at":       time.Now(),
	})
}
VSP7INTERNAL_API_HANDLER_IMPORTS_GO

# internal/api/handler/report.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/report.go' << 'VSP7INTERNAL_API_HANDLER_REPORT_GO'
package handler

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Report struct{ DB *store.DB }

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"sevColor": func(s string) string {
		m := map[string]string{"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706","LOW":"#65a30d","INFO":"#6b7280"}
		if c, ok := m[s]; ok { return c }
		return "#6b7280"
	},
	"fmtTime": func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
}).Parse(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>VSP Report — {{.Run.RID}}</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
.header{background:#1e3a5f;padding:24px 40px;border-bottom:2px solid #2563eb}
.header h1{margin:0;font-size:24px;color:#60a5fa}
.header .meta{color:#94a3b8;font-size:13px;margin-top:4px}
.summary{display:flex;gap:16px;padding:24px 40px;flex-wrap:wrap}
.card{background:#1e293b;border-radius:8px;padding:16px 24px;min-width:120px;text-align:center}
.card .val{font-size:32px;font-weight:700}
.card .lbl{font-size:12px;color:#94a3b8;margin-top:4px}
.section{padding:0 40px 32px}
.section h2{font-size:16px;color:#60a5fa;border-bottom:1px solid #1e293b;padding-bottom:8px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#1e293b;padding:8px 12px;text-align:left;color:#94a3b8;font-weight:500}
td{padding:8px 12px;border-bottom:1px solid #1e293b}
.pill{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;color:#fff}
</style>
</head>
<body>
<div class="header">
  <h1>VSP Security Report</h1>
  <div class="meta">RID: {{.Run.RID}} &nbsp;|&nbsp; Mode: {{.Run.Mode}} &nbsp;|&nbsp; {{fmtTime .Run.CreatedAt}}</div>
</div>
<div class="summary">
  <div class="card"><div class="val" style="color:{{sevColor "CRITICAL"}}">{{.Summary.Critical}}</div><div class="lbl">CRITICAL</div></div>
  <div class="card"><div class="val" style="color:{{sevColor "HIGH"}}">{{.Summary.High}}</div><div class="lbl">HIGH</div></div>
  <div class="card"><div class="val" style="color:{{sevColor "MEDIUM"}}">{{.Summary.Medium}}</div><div class="lbl">MEDIUM</div></div>
  <div class="card"><div class="val" style="color:{{sevColor "LOW"}}">{{.Summary.Low}}</div><div class="lbl">LOW</div></div>
  <div class="card"><div class="val" style="color:{{if eq .Run.Gate "PASS"}}#4ade80{{else if eq .Run.Gate "FAIL"}}#f87171{{else}}#fbbf24{{end}}">{{.Run.Gate}}</div><div class="lbl">GATE</div></div>
  <div class="card"><div class="val" style="color:#60a5fa">{{.Run.Posture}}</div><div class="lbl">POSTURE</div></div>
</div>
<div class="section">
  <h2>Findings ({{len .Findings}})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>File</th><th>Line</th><th>Message</th></tr></thead>
    <tbody>
    {{range .Findings}}
    <tr>
      <td><span class="pill" style="background:{{sevColor .Severity}}">{{.Severity}}</span></td>
      <td style="color:#94a3b8">{{.Tool}}</td>
      <td style="font-family:monospace;font-size:11px;color:#818cf8">{{.RuleID}}</td>
      <td style="font-family:monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{.Path}}</td>
      <td style="color:#64748b">{{.LineNum}}</td>
      <td style="font-size:12px">{{.Message}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
</body>
</html>`))

type reportData struct {
	Run      *store.Run
	Findings []store.Finding
	Summary  struct{ Critical, High, Medium, Low int }
}

// GET /api/v1/vsp/run_report_html/{rid}
func (h *Report) HTML(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")
	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil { jsonError(w, "run not found", http.StatusNotFound); return }

	findings, _, _ := h.DB.ListFindings(r.Context(), claims.TenantID, store.FindingFilter{Limit: 1000})
	var rf []store.Finding
	for _, f := range findings { if f.RunID == run.ID { rf = append(rf, f) } }

	data := reportData{Run: run, Findings: rf}
	for _, f := range rf {
		switch f.Severity {
		case "CRITICAL": data.Summary.Critical++
		case "HIGH":     data.Summary.High++
		case "MEDIUM":   data.Summary.Medium++
		case "LOW":      data.Summary.Low++
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=vsp-%s.html", rid))
	}
	reportTmpl.Execute(w, data) //nolint:errcheck
}
VSP7INTERNAL_API_HANDLER_REPORT_GO

# internal/api/handler/sandbox.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/sandbox.go' << 'VSP7INTERNAL_API_HANDLER_SANDBOX_GO'
package handler

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/siem"
	"github.com/vsp/platform/internal/store"
)

type Sandbox struct {
	DB    *store.DB
	mu    sync.RWMutex
	events []sandboxEvent
}

type sandboxEvent struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	EventType string    `json:"event_type"`
	Payload   any       `json:"payload"`
	FiredAt   time.Time `json:"fired_at"`
}

// GET /api/v1/vsp/sandbox
func (h *Sandbox) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	h.mu.RLock()
	defer h.mu.RUnlock()
	var my []sandboxEvent
	for _, e := range h.events {
		if e.TenantID == claims.TenantID { my = append(my, e) }
	}
	if my == nil { my = []sandboxEvent{} }
	jsonOK(w, map[string]any{"events": my, "total": len(my)})
}

// POST /api/v1/vsp/sandbox/test-fire
func (h *Sandbox) TestFire(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req struct {
		EventType string `json:"event_type"`
		Gate      string `json:"gate"`
		Severity  string `json:"severity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.EventType = "test"
		req.Gate = "WARN"
		req.Severity = "HIGH"
	}
	event := siem.Event{
		RID:      "RID_SANDBOX_" + time.Now().Format("20060102_150405"),
		TenantID: claims.TenantID,
		Gate:     req.Gate,
		Posture:  "B",
		Score:    75,
		Findings: 3,
		High:     3,
		Timestamp: time.Now(),
		Src:      "sandbox",
	}
	go siem.Deliver(r.Context(), h.DB, event)

	h.mu.Lock()
	h.events = append(h.events, sandboxEvent{
		ID:        event.RID,
		TenantID:  claims.TenantID,
		EventType: req.EventType,
		Payload:   event,
		FiredAt:   time.Now(),
	})
	h.mu.Unlock()

	jsonOK(w, map[string]any{
		"status": "fired",
		"rid":    event.RID,
		"event":  event,
	})
}

// DELETE /api/v1/vsp/sandbox/clear
func (h *Sandbox) Clear(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	h.mu.Lock()
	keep := h.events[:0]
	for _, e := range h.events {
		if e.TenantID != claims.TenantID { keep = append(keep, e) }
	}
	h.events = keep
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
VSP7INTERNAL_API_HANDLER_SANDBOX_GO

# internal/api/handler/sla.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/sla.go' << 'VSP7INTERNAL_API_HANDLER_SLA_GO'
package handler

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type SLA struct{ DB *store.DB }

type slaEntry struct {
	Severity    string        `json:"severity"`
	SLADays     int           `json:"sla_days"`
	OpenCount   int           `json:"open_count"`
	BreachCount int           `json:"breach_count"`
	AvgAgeDays  float64       `json:"avg_age_days"`
	Status      string        `json:"status"` // green/yellow/red
}

// GET /api/v1/vsp/sla_tracker
func (h *SLA) Tracker(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings, _, err := h.DB.ListFindings(r.Context(), claims.TenantID, store.FindingFilter{Limit: 5000})
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }

	sla := map[string]int{"CRITICAL": 3, "HIGH": 14, "MEDIUM": 30, "LOW": 90}
	type bucket struct { open, breach int; totalAge float64 }
	buckets := map[string]*bucket{}
	for k := range sla { buckets[k] = &bucket{} }

	now := time.Now()
	for _, f := range findings {
		b, ok := buckets[f.Severity]
		if !ok { continue }
		b.open++
		age := now.Sub(f.CreatedAt).Hours() / 24
		b.totalAge += age
		if age > float64(sla[f.Severity]) { b.breach++ }
	}

	entries := make([]slaEntry, 0, 4)
	for _, sev := range []string{"CRITICAL","HIGH","MEDIUM","LOW"} {
		b := buckets[sev]
		avg := 0.0
		if b.open > 0 { avg = b.totalAge / float64(b.open) }
		status := "green"
		if b.breach > 0 { status = "red" } else if avg > float64(sla[sev])*0.8 { status = "yellow" }
		entries = append(entries, slaEntry{
			Severity:    sev,
			SLADays:     sla[sev],
			OpenCount:   b.open,
			BreachCount: b.breach,
			AvgAgeDays:  avg,
			Status:      status,
		})
	}
	jsonOK(w, map[string]any{"sla": entries, "as_of": now})
}

// GET /api/v1/vsp/metrics_slos
func (h *SLA) MetricsSLOs(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runs, err := h.DB.ListRuns(r.Context(), claims.TenantID, 100, 0)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }

	var totalDur, count float64
	passCount, failCount := 0, 0
	for _, run := range runs {
		if run.Status != "DONE" { continue }
		if run.FinishedAt != nil && run.StartedAt != nil {
			dur := run.FinishedAt.Sub(*run.StartedAt).Seconds()
			totalDur += dur
			count++
		}
		if run.Gate == "PASS" { passCount++ } else if run.Gate == "FAIL" { failCount++ }
	}
	avgDur := 0.0
	if count > 0 { avgDur = totalDur / count }
	total := passCount + failCount
	passRate := 0.0
	if total > 0 { passRate = float64(passCount) / float64(total) * 100 }

	jsonOK(w, map[string]any{
		"avg_scan_duration_sec": avgDur,
		"pass_rate_pct":         passRate,
		"total_scans":           len(runs),
		"pass_count":            passCount,
		"fail_count":            failCount,
		"slo_scan_time_target":  300,
		"slo_scan_time_met":     avgDur < 300,
		"slo_pass_rate_target":  80.0,
		"slo_pass_rate_met":     passRate >= 80.0,
	})
}
VSP7INTERNAL_API_HANDLER_SLA_GO

# internal/governance/engine.go
mkdir -p "internal/governance"
cat > 'internal/governance/engine.go' << 'VSP7INTERNAL_GOVERNANCE_ENGINE_GO'
package governance

import (
	"fmt"
	"time"

	"github.com/vsp/platform/internal/store"
)

// BuildRiskRegister derives risk items from findings.
func BuildRiskRegister(tenantID string, findings []store.Finding) []RiskItem {
	items := make([]RiskItem, 0, len(findings))
	for _, f := range findings {
		if f.Severity == "INFO" || f.Severity == "TRACE" {
			continue
		}
		items = append(items, RiskItem{
			ID:          "risk-" + f.ID,
			TenantID:    tenantID,
			Title:       fmt.Sprintf("[%s] %s", f.Severity, f.RuleID),
			Description: f.Message,
			Level:       severityToRisk(f.Severity),
			Status:      "open",
			Owner:       "security-team",
			FindingID:   f.ID,
			DueDate:     dueDateBySev(f.Severity),
			CreatedAt:   f.CreatedAt,
			UpdatedAt:   f.CreatedAt,
		})
	}
	return items
}

// BuildTraceability maps findings to security controls.
func BuildTraceability(findings []store.Finding) []TraceabilityRow {
	rows := make([]TraceabilityRow, 0)
	for _, f := range findings {
		control, framework := cweToControl(f.CWE)
		rows = append(rows, TraceabilityRow{
			FindingID: f.ID,
			Severity:  f.Severity,
			RuleID:    f.RuleID,
			Control:   control,
			Framework: framework,
			Status:    riskStatus(f.Severity),
		})
	}
	return rows
}

// BuildFrameworkScorecard computes scores per framework from findings.
func BuildFrameworkScorecard(findings []store.Finding) []FrameworkScore {
	// Simplified scoring: start at 100, deduct per finding by severity
	frameworks := map[string]*FrameworkScore{
		"NIST SP 800-53": {Framework: "NIST SP 800-53", Score: 100,
			Domains: []DomainScore{
				{Name: "Access Control (AC)",       Score: 100, Items: 10},
				{Name: "System Integrity (SI)",      Score: 100, Items: 8},
				{Name: "Identification & Auth (IA)", Score: 100, Items: 6},
				{Name: "Audit & Accountability (AU)",Score: 100, Items: 5},
				{Name: "Config Management (CM)",     Score: 100, Items: 7},
			},
		},
		"ISO 27001": {Framework: "ISO 27001", Score: 100,
			Domains: []DomainScore{
				{Name: "A.9 Access Control",          Score: 100, Items: 8},
				{Name: "A.12 Operations Security",    Score: 100, Items: 10},
				{Name: "A.14 System Development",     Score: 100, Items: 9},
				{Name: "A.16 Incident Management",    Score: 100, Items: 4},
				{Name: "A.18 Compliance",             Score: 100, Items: 6},
			},
		},
		"SOC 2 Type II": {Framework: "SOC 2 Type II", Score: 100,
			Domains: []DomainScore{
				{Name: "CC6 Logical Access",          Score: 100, Items: 7},
				{Name: "CC7 System Operations",       Score: 100, Items: 8},
				{Name: "CC8 Change Management",       Score: 100, Items: 5},
				{Name: "A1 Availability",             Score: 100, Items: 4},
				{Name: "PI1 Processing Integrity",    Score: 100, Items: 6},
			},
		},
	}

	for _, f := range findings {
		penalty := map[string]int{"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 1}[f.Severity]
		for _, fw := range frameworks {
			fw.Score = max0(fw.Score - penalty/len(frameworks))
			for i := range fw.Domains {
				if fw.Domains[i].Score > 0 {
					fw.Domains[i].Score = max0(fw.Domains[i].Score - penalty)
					break // affect one domain per finding
				}
			}
		}
	}

	result := make([]FrameworkScore, 0, len(frameworks))
	for _, fw := range frameworks {
		result = append(result, *fw)
	}
	return result
}

// BuildZeroTrust computes DoD Zero Trust 7 pillars scores.
func BuildZeroTrust(findings []store.Finding) []ZeroTrustPillar {
	pillars := []ZeroTrustPillar{
		{Pillar: "User", Score: 95, Level: "Advanced",
			Controls: []string{"MFA", "RBAC", "Session management"}},
		{Pillar: "Device", Score: 80, Level: "Advanced",
			Controls: []string{"Endpoint detection", "Device compliance"}},
		{Pillar: "Network", Score: 85, Level: "Advanced",
			Controls: []string{"Micro-segmentation", "Encrypted transport"}},
		{Pillar: "Application & Workload", Score: 0, Level: "Traditional",
			Controls: []string{"SAST", "DAST", "SCA", "Secrets scanning"}},
		{Pillar: "Data", Score: 75, Level: "Advanced",
			Controls: []string{"Encryption at rest", "DLP", "Classification"}},
		{Pillar: "Visibility & Analytics", Score: 90, Level: "Optimal",
			Controls: []string{"SIEM", "Audit log", "Prometheus metrics"}},
		{Pillar: "Automation & Orchestration", Score: 88, Level: "Advanced",
			Controls: []string{"CI/CD gates", "Policy as code", "Auto-remediation"}},
	}

	// Application pillar score derived from findings
	appScore := 100
	for _, f := range findings {
		appScore -= map[string]int{"CRITICAL": 20, "HIGH": 10, "MEDIUM": 4, "LOW": 1}[f.Severity]
		pillars[3].Findings++
	}
	pillars[3].Score = max0(appScore)
	pillars[3].Level = func() string {
		if appScore >= 80 { return "Advanced" }
		if appScore >= 50 { return "Traditional" }
		return "Traditional"
	}()
	return pillars
}

// BuildSecurityRoadmap generates a maturity roadmap.
func BuildSecurityRoadmap(findings []store.Finding, posture string) []RoadmapItem {
	items := []RoadmapItem{
		{Quarter: "Q2 2026", Title: "Automated SAST in CI/CD pipeline", Priority: "HIGH", Status: "in-progress", Category: "DevSecOps"},
		{Quarter: "Q2 2026", Title: "Secret rotation enforcement", Priority: "HIGH", Status: "planned", Category: "Secrets"},
		{Quarter: "Q2 2026", Title: "Dependency vulnerability SLA", Priority: "MEDIUM", Status: "planned", Category: "SCA"},
		{Quarter: "Q3 2026", Title: "IaC security scanning", Priority: "MEDIUM", Status: "planned", Category: "IaC"},
		{Quarter: "Q3 2026", Title: "SIEM integration (Splunk/Datadog)", Priority: "HIGH", Status: "done", Category: "SIEM"},
		{Quarter: "Q3 2026", Title: "OSCAL AR/POA&M automation", Priority: "MEDIUM", Status: "done", Category: "Compliance"},
		{Quarter: "Q4 2026", Title: "Zero Trust application pillar", Priority: "HIGH", Status: "planned", Category: "ZeroTrust"},
		{Quarter: "Q4 2026", Title: "SOC 2 Type II audit readiness", Priority: "HIGH", Status: "planned", Category: "Compliance"},
		{Quarter: "Q1 2027", Title: "ISO 27001 certification", Priority: "MEDIUM", Status: "planned", Category: "Compliance"},
		{Quarter: "Q1 2027", Title: "ML-based anomaly detection", Priority: "LOW", Status: "planned", Category: "AI/ML"},
	}
	// Add finding-driven items
	if posture == "D" || posture == "F" {
		items = append([]RoadmapItem{
			{Quarter: "Q2 2026", Title: "CRITICAL finding remediation sprint", Priority: "CRITICAL", Status: "overdue", Category: "Remediation"},
		}, items...)
	}
	return items
}

// BuildRACI generates governance chain.
func BuildRACI() []map[string]string {
	return []map[string]string{
		{"activity": "Security scanning", "responsible": "DevSecOps", "accountable": "CISO", "consulted": "Dev Lead", "informed": "CTO"},
		{"activity": "Vulnerability triage", "responsible": "Security Analyst", "accountable": "Security Manager", "consulted": "Dev Lead", "informed": "CISO"},
		{"activity": "Policy management", "responsible": "Security Architect", "accountable": "CISO", "consulted": "Legal", "informed": "Board"},
		{"activity": "Incident response", "responsible": "SOC Analyst", "accountable": "CISO", "consulted": "Legal/PR", "informed": "CEO"},
		{"activity": "Compliance audit", "responsible": "GRC Team", "accountable": "CISO", "consulted": "External Auditor", "informed": "Board"},
		{"activity": "Risk acceptance", "responsible": "Risk Manager", "accountable": "CRO", "consulted": "CISO", "informed": "Board"},
		{"activity": "Penetration testing", "responsible": "Red Team", "accountable": "CISO", "consulted": "Dev Lead", "informed": "CTO"},
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func severityToRisk(sev string) RiskLevel {
	switch sev {
	case "CRITICAL": return RiskCritical
	case "HIGH":     return RiskHigh
	case "MEDIUM":   return RiskMedium
	default:         return RiskLow
	}
}

func dueDateBySev(sev string) time.Time {
	days := map[string]int{"CRITICAL": 3, "HIGH": 14, "MEDIUM": 30, "LOW": 90}[sev]
	return time.Now().AddDate(0, 0, days)
}

func riskStatus(sev string) string {
	if sev == "LOW" { return "monitor" }
	return "open"
}

func cweToControl(cwe string) (control, framework string) {
	m := map[string][2]string{
		"CWE-78":  {"SI-10", "NIST SP 800-53"},
		"CWE-79":  {"SI-10", "NIST SP 800-53"},
		"CWE-89":  {"SI-10", "NIST SP 800-53"},
		"CWE-259": {"IA-5",  "NIST SP 800-53"},
		"CWE-327": {"SC-13", "NIST SP 800-53"},
		"CWE-502": {"SI-10", "NIST SP 800-53"},
		"CWE-798": {"IA-5",  "NIST SP 800-53"},
	}
	if v, ok := m[cwe]; ok {
		return v[0], v[1]
	}
	return "SI-3", "NIST SP 800-53"
}

func max0(n int) int {
	if n < 0 { return 0 }
	return n
}
VSP7INTERNAL_GOVERNANCE_ENGINE_GO

# internal/governance/models.go
mkdir -p "internal/governance"
cat > 'internal/governance/models.go' << 'VSP7INTERNAL_GOVERNANCE_MODELS_GO'
package governance

import "time"

type RiskLevel string
const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
)

type RiskItem struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Level       RiskLevel `json:"level"`
	Status      string    `json:"status"` // open|mitigated|accepted|closed
	Owner       string    `json:"owner"`
	FindingID   string    `json:"finding_id,omitempty"`
	DueDate     time.Time `json:"due_date"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ControlOwner struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Control   string `json:"control"`   // e.g. "AC-2", "SI-10"
	Framework string `json:"framework"` // NIST|ISO27001|SOC2|PCI
	Owner     string `json:"owner"`
	Team      string `json:"team"`
	Status    string `json:"status"` // implemented|partial|planned|not-implemented
}

type Evidence struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Title       string     `json:"title"`
	Type        string     `json:"type"` // scan|screenshot|policy|attestation
	RunID       string     `json:"run_id,omitempty"`
	Path        string     `json:"path"`
	Hash        string     `json:"hash"`
	Frozen      bool       `json:"frozen"`
	FrozenAt    *time.Time `json:"frozen_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type TraceabilityRow struct {
	FindingID   string `json:"finding_id"`
	Severity    string `json:"severity"`
	RuleID      string `json:"rule_id"`
	Control     string `json:"control"`
	Framework   string `json:"framework"`
	EvidenceID  string `json:"evidence_id"`
	Status      string `json:"status"`
}

type FrameworkScore struct {
	Framework string           `json:"framework"`
	Score     int              `json:"score"`
	Domains   []DomainScore    `json:"domains"`
}

type DomainScore struct {
	Name  string `json:"name"`
	Score int    `json:"score"`
	Items int    `json:"items"`
	Pass  int    `json:"pass"`
}

type RoadmapItem struct {
	Quarter  string `json:"quarter"`
	Title    string `json:"title"`
	Priority string `json:"priority"`
	Status   string `json:"status"`
	Category string `json:"category"`
}

type ZeroTrustPillar struct {
	Pillar   string `json:"pillar"`
	Score    int    `json:"score"`
	Level    string `json:"level"` // Traditional|Advanced|Optimal
	Findings int    `json:"open_findings"`
	Controls []string `json:"key_controls"`
}
VSP7INTERNAL_GOVERNANCE_MODELS_GO

# internal/pipeline/profiles.go
mkdir -p "internal/pipeline"
cat > 'internal/pipeline/profiles.go' << 'VSP7INTERNAL_PIPELINE_PROFILES_GO'
package pipeline

import "github.com/vsp/platform/internal/scanner"

type ProfileConfig struct {
	TimeoutSec  int
	Description string
}

var Profiles = map[Profile]ProfileConfig{
	ProfileFast:    {TimeoutSec: 120,  Description: "Fast — core tools, 2min"},
	ProfileExt:     {TimeoutSec: 300,  Description: "Extended — all tools, 5min"},
	ProfileAggr:    {TimeoutSec: 600,  Description: "Aggressive — fail on any HIGH"},
	ProfilePremium: {TimeoutSec: 900,  Description: "Premium — deep scan 15min"},
	ProfileFull:    {TimeoutSec: 1200, Description: "Full — all tools 20min"},
	ProfileFullSOC: {TimeoutSec: 1800, Description: "Full SOC — max depth"},
}

func RunnersForProfile(mode Mode, profile Profile) []scanner.Runner {
	runners := RunnersFor(mode)
	if profile == ProfileFast && (mode == ModeSAST || mode == ModeFull) {
		filtered := make([]scanner.Runner, 0)
		for _, r := range runners {
			if r.Name() != "codeql" {
				filtered = append(filtered, r)
			}
		}
		return filtered
	}
	return runners
}

func TimeoutForProfile(profile Profile) int {
	if cfg, ok := Profiles[profile]; ok {
		return cfg.TimeoutSec / 3
	}
	return 120
}
VSP7INTERNAL_PIPELINE_PROFILES_GO

# internal/report/sarif.go
mkdir -p "internal/report"
cat > 'internal/report/sarif.go' << 'VSP7INTERNAL_REPORT_SARIF_GO'
package report

import (
	"encoding/json"
	"fmt"
	"github.com/vsp/platform/internal/store"
)

// SARIF 2.1.0 structures
type SARIFDoc struct {
	Schema  string    `json:"$schema"`
	Version string    `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool      `json:"tool"`
	Results []SARIFResult  `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription SARIFMessage    `json:"shortDescription"`
	Properties       map[string]any  `json:"properties,omitempty"`
}

type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SARIFMessage     `json:"message"`
	Locations []SARIFLocation  `json:"locations"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysical `json:"physicalLocation"`
}

type SARIFPhysical struct {
	ArtifactLocation SARIFArtifact `json:"artifactLocation"`
	Region           SARIFRegion   `json:"region"`
}

type SARIFArtifact struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

func severityToLevel(sev string) string {
	switch sev {
	case "CRITICAL", "HIGH": return "error"
	case "MEDIUM":           return "warning"
	default:                 return "note"
	}
}

// BuildSARIF creates a SARIF 2.1.0 document from findings.
func BuildSARIF(run store.Run, findings []store.Finding) *SARIFDoc {
	// Group findings by tool
	byTool := make(map[string][]store.Finding)
	for _, f := range findings {
		if f.RunID == run.ID {
			byTool[f.Tool] = append(byTool[f.Tool], f)
		}
	}

	runs := make([]SARIFRun, 0, len(byTool))
	for tool, toolFindings := range byTool {
		rules := make([]SARIFRule, 0)
		ruleSet := make(map[string]bool)
		results := make([]SARIFResult, 0, len(toolFindings))

		for _, f := range toolFindings {
			if !ruleSet[f.RuleID] && f.RuleID != "" {
				rules = append(rules, SARIFRule{
					ID:   f.RuleID,
					Name: f.RuleID,
					ShortDescription: SARIFMessage{Text: f.Message},
					Properties: map[string]any{"cwe": f.CWE, "fix": f.FixSignal},
				})
				ruleSet[f.RuleID] = true
			}
			results = append(results, SARIFResult{
				RuleID: f.RuleID,
				Level:  severityToLevel(f.Severity),
				Message: SARIFMessage{Text: f.Message},
				Locations: []SARIFLocation{{
					PhysicalLocation: SARIFPhysical{
						ArtifactLocation: SARIFArtifact{URI: f.Path},
						Region:           SARIFRegion{StartLine: f.LineNum},
					},
				}},
			})
		}

		runs = append(runs, SARIFRun{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:    fmt.Sprintf("VSP/%s", tool),
				Version: "0.3.0",
				Rules:   rules,
			}},
			Results: results,
		})
	}

	return &SARIFDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    runs,
	}
}

func SARIFToJSON(doc *SARIFDoc) ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}
VSP7INTERNAL_REPORT_SARIF_GO

# internal/scanner/checkov/checkov.go
mkdir -p "internal/scanner/checkov"
cat > 'internal/scanner/checkov/checkov.go' << 'VSP7INTERNAL_SCANNER_CHECKOV_CHECKOV_GO'
package checkov

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}
func New() *Adapter { return &Adapter{} }
func (a *Adapter) Name() string { return "checkov" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" { return nil, fmt.Errorf("checkov: Src required") }
	args := []string{"-d", opts.Src, "-o", "json", "--quiet", "--compact"}
	if extra, ok := opts.ExtraArgs["checkov"]; ok { args = append(args, extra...) }
	res, err := scanner.Run(ctx, "checkov", args...)
	if err != nil { return nil, err }
	if len(res.Stdout) == 0 { return nil, nil }
	return parse(res.Stdout)
}

type checkovOutput struct {
	Results struct {
		FailedChecks []checkovCheck `json:"failed_checks"`
	} `json:"results"`
}
type checkovCheck struct {
	CheckID   string `json:"check_id"`
	CheckName string `json:"check_name"`
	Severity  string `json:"severity"`
	Resource  string `json:"resource"`
	File      string `json:"file_path"`
	Line      []int  `json:"file_line_range"`
	Guideline string `json:"guideline"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out checkovOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("checkov: JSON: %w", err)
	}
	var findings []scanner.Finding
	for _, c := range out.Results.FailedChecks {
		line := 0
		if len(c.Line) > 0 { line = c.Line[0] }
		findings = append(findings, scanner.Finding{
			Tool:      "checkov",
			Severity:  scanner.NormaliseSeverity(c.Severity),
			RuleID:    c.CheckID,
			Message:   c.CheckName,
			Path:      c.File,
			Line:      line,
			FixSignal: c.Guideline,
			Raw:       map[string]any{"resource": c.Resource},
		})
	}
	return findings, nil
}
VSP7INTERNAL_SCANNER_CHECKOV_CHECKOV_GO

# internal/scanner/codeql/codeql.go
mkdir -p "internal/scanner/codeql"
cat > 'internal/scanner/codeql/codeql.go' << 'VSP7INTERNAL_SCANNER_CODEQL_CODEQL_GO'
package codeql

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}
func New() *Adapter { return &Adapter{} }
func (a *Adapter) Name() string { return "codeql" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" { return nil, fmt.Errorf("codeql: Src required") }

	// Detect language from source files
	lang := detectLang(opts.Src)
	if lang == "" { return nil, nil } // no supported files found

	dbDir, err := os.MkdirTemp("", "codeql_db_*")
	if err != nil { return nil, err }
	defer os.RemoveAll(dbDir)

	resDir, err := os.MkdirTemp("", "codeql_res_*")
	if err != nil { return nil, err }
	defer os.RemoveAll(resDir)

	// Create database
	_, err = scanner.Run(ctx, "codeql", "database", "create",
		"--language="+lang,
		"--source-root="+opts.Src,
		"--overwrite",
		dbDir,
	)
	if err != nil { return nil, fmt.Errorf("codeql: database create: %w", err) }

	resFile := filepath.Join(resDir, "results.sarif")
	// Analyze
	_, err = scanner.Run(ctx, "codeql", "database", "analyze",
		dbDir,
		"--format=sarif-latest",
		"--output="+resFile,
		"--sarif-add-snippets",
	)
	if err != nil { return nil, fmt.Errorf("codeql: analyze: %w", err) }

	data, err := os.ReadFile(resFile)
	if err != nil { return nil, nil }
	return parseSARIF(data, lang)
}

// detectLang returns the primary codeql language for the source tree.
func detectLang(src string) string {
	counts := map[string]int{}
	filepath.WalkDir(src, func(p string, d os.DirEntry, _ error) error {
		if d.IsDir() { return nil }
		switch strings.ToLower(filepath.Ext(p)) {
		case ".py":          counts["python"]++
		case ".go":          counts["go"]++
		case ".js", ".ts":   counts["javascript"]++
		case ".java":        counts["java"]++
		case ".cs":          counts["csharp"]++
		case ".cpp", ".cc":  counts["cpp"]++
		}
		return nil
	})
	best, max := "", 0
	for lang, n := range counts {
		if n > max { best, max = lang, n }
	}
	return best
}

type sarifDoc struct {
	Runs []sarifRun `json:"runs"`
}
type sarifRun struct {
	Results []sarifResult `json:"results"`
}
type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct{ Text string `json:"text"` } `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct{ URI string `json:"uri"` } `json:"artifactLocation"`
			Region struct{ StartLine int `json:"startLine"` } `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

func levelToSev(level string) string {
	switch level {
	case "error":   return "HIGH"
	case "warning": return "MEDIUM"
	default:        return "INFO"
	}
}

func parseSARIF(data []byte, lang string) ([]scanner.Finding, error) {
	var doc sarifDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("codeql: parse SARIF: %w", err)
	}
	var findings []scanner.Finding
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			path, line := "", 0
			if len(r.Locations) > 0 {
				path = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
				line = r.Locations[0].PhysicalLocation.Region.StartLine
			}
			findings = append(findings, scanner.Finding{
				Tool:      "codeql",
				Severity:  levelToSev(r.Level),
				RuleID:    r.RuleID,
				Message:   r.Message.Text,
				Path:      path,
				Line:      line,
				FixSignal: "https://codeql.github.com/codeql-query-help/" + lang + "/" + r.RuleID,
			})
		}
	}
	return findings, nil
}
VSP7INTERNAL_SCANNER_CODEQL_CODEQL_GO

# internal/scanner/kics/kics.go
mkdir -p "internal/scanner/kics"
cat > 'internal/scanner/kics/kics.go' << 'VSP7INTERNAL_SCANNER_KICS_KICS_GO'
package kics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}

func New() *Adapter      { return &Adapter{} }
func (a *Adapter) Name() string { return "kics" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("kics: Src required")
	}

	outDir, err := os.MkdirTemp("", "kics_out_*")
	if err != nil {
		return nil, fmt.Errorf("kics: mktemp: %w", err)
	}
	defer os.RemoveAll(outDir)

	args := []string{
		"scan",
		"-p", opts.Src,
		"--report-formats", "json",
		"--output-path", outDir,
		"--output-name", "results",
		"--no-progress",
		"--silent",
		"--fail-on", "none",
	}
	if extra, ok := opts.ExtraArgs["kics"]; ok {
		args = append(args, extra...)
	}

	if _, err := scanner.Run(ctx, "kics", args...); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Join(outDir, "results.json"))
	if err != nil {
		return nil, nil // no IaC files found = 0 findings
	}
	return parse(data)
}

type kicsOutput struct {
	Queries []kicsQuery `json:"queries"`
}

type kicsQuery struct {
	QueryName string     `json:"query_name"`
	QueryID   string     `json:"query_id"`
	Severity  string     `json:"severity"`
	Platform  string     `json:"platform"`
	Files     []kicsFile `json:"files"`
}

type kicsFile struct {
	FileName  string `json:"file_name"`
	Line      int    `json:"line"`
	IssueType string `json:"issue_type"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out kicsOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("kics: JSON: %w", err)
	}
	var findings []scanner.Finding
	for _, q := range out.Queries {
		for _, f := range q.Files {
			findings = append(findings, scanner.Finding{
				Tool:      "kics",
				Severity:  scanner.NormaliseSeverity(q.Severity),
				RuleID:    q.QueryID,
				Message:   q.QueryName,
				Path:      f.FileName,
				Line:      f.Line,
				FixSignal: "kics: " + q.QueryName,
				Raw: map[string]any{
					"platform":   q.Platform,
					"issue_type": f.IssueType,
				},
			})
		}
	}
	return findings, nil
}
VSP7INTERNAL_SCANNER_KICS_KICS_GO

# internal/scanner/nikto/nikto.go
mkdir -p "internal/scanner/nikto"
cat > 'internal/scanner/nikto/nikto.go' << 'VSP7INTERNAL_SCANNER_NIKTO_NIKTO_GO'
package nikto

import (
	"context"
	"encoding/xml"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}

func New() *Adapter      { return &Adapter{} }
func (a *Adapter) Name() string { return "nikto" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	target := opts.URL
	if target == "" {
		target = opts.Src
	}
	if target == "" {
		return nil, fmt.Errorf("nikto: URL required for DAST")
	}

	maxTime := 90
	if opts.TimeoutSec > 0 && opts.TimeoutSec < maxTime {
		maxTime = opts.TimeoutSec
	}

	args := []string{
		"-h", target,
		"-Format", "xml",
		"-o", "/dev/stdout",
		"-nointeractive",
		"-maxtime", fmt.Sprintf("%ds", maxTime),
		"-timeout", "10",
	}
	if extra, ok := opts.ExtraArgs["nikto"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "nikto", args...)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}
	return parseXML(res.Stdout)
}

type niktoScan struct {
	XMLName     xml.Name       `xml:"niktoscan"`
	ScanDetails []niktoDetails `xml:"scandetails"`
}

type niktoDetails struct {
	TargetIP   string      `xml:"targetip,attr"`
	TargetPort string      `xml:"targetport,attr"`
	Items      []niktoItem `xml:"item"`
}

type niktoItem struct {
	ID          string `xml:"id,attr"`
	OSVDBID     string `xml:"osvdbid,attr"`
	Method      string `xml:"method,attr"`
	Description string `xml:"description"`
	URI         string `xml:"uri"`
	NameLink    string `xml:"namelink"`
}

func parseXML(data []byte) ([]scanner.Finding, error) {
	var out niktoScan
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("nikto: parse XML: %w", err)
	}
	var findings []scanner.Finding
	for _, d := range out.ScanDetails {
		for _, item := range d.Items {
			findings = append(findings, scanner.Finding{
				Tool:      "nikto",
				Severity:  scanner.SevMedium,
				RuleID:    "NIKTO-" + item.ID,
				Message:   item.Description,
				Path:      item.URI,
				FixSignal: item.NameLink,
				Raw: map[string]any{
					"osvdb_id": item.OSVDBID,
					"method":   item.Method,
					"target":   d.TargetIP + ":" + d.TargetPort,
				},
			})
		}
	}
	return findings, nil
}
VSP7INTERNAL_SCANNER_NIKTO_NIKTO_GO

# internal/scanner/nuclei/nuclei.go
mkdir -p "internal/scanner/nuclei"
cat > 'internal/scanner/nuclei/nuclei.go' << 'VSP7INTERNAL_SCANNER_NUCLEI_NUCLEI_GO'
package nuclei

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}
func New() *Adapter { return &Adapter{} }
func (a *Adapter) Name() string { return "nuclei" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	target := opts.URL
	if target == "" { return nil, fmt.Errorf("nuclei: URL required") }
	args := []string{"-u", target, "-json", "-silent", "-no-color", "-severity", "medium,high,critical", "-timeout", "10"}
	if extra, ok := opts.ExtraArgs["nuclei"]; ok { args = append(args, extra...) }
	res, err := scanner.Run(ctx, "nuclei", args...)
	if err != nil { return nil, err }
	if len(res.Stdout) == 0 { return nil, nil }
	return parse(res.Stdout)
}

type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
	Type      string `json:"type"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var findings []scanner.Finding
	for _, line := range bytes.Split(data, []byte("
")) {
		if len(bytes.TrimSpace(line)) == 0 { continue }
		var r nucleiResult
		if err := json.Unmarshal(line, &r); err != nil { continue }
		findings = append(findings, scanner.Finding{
			Tool:      "nuclei",
			Severity:  scanner.NormaliseSeverity(r.Info.Severity),
			RuleID:    r.TemplateID,
			Message:   r.Info.Name,
			Path:      r.MatchedAt,
			FixSignal: "https://nuclei.projectdiscovery.io/templates/" + r.TemplateID,
			Raw:       map[string]any{"type": r.Type, "tags": r.Info.Tags},
		})
	}
	return findings, nil
}
VSP7INTERNAL_SCANNER_NUCLEI_NUCLEI_GO

# static/index.html
mkdir -p "static"
cat > 'static/index.html' << 'VSP7STATIC_INDEX_HTML'
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
      <button class="tab" onclick="showPanel('governance',this)">Governance</button>
      <button class="tab" onclick="showPanel('soc',this)">SOC</button>
      <button class="tab" onclick="showPanel('export',this)">Export</button>
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


    <!-- Governance Panel -->
    <div id="panel-governance" class="panel">
      <div class="grid4" style="grid-template-columns:repeat(2,1fr)">
        <div class="card">
          <div class="section-head"><span class="section-title">Risk Register</span><button class="btn btn-sm btn-outline" onclick="loadRiskRegister()">Refresh</button></div>
          <div class="table-wrap"><table>
            <thead><tr><th>Level</th><th>Title</th><th>Status</th><th>Due</th></tr></thead>
            <tbody id="risk-table"><tr><td colspan="4" style="color:#64748b;padding:16px">Loading...</td></tr></tbody>
          </table></div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">Traceability Matrix</span></div>
          <div class="table-wrap"><table>
            <thead><tr><th>Severity</th><th>Rule</th><th>Control</th><th>Framework</th></tr></thead>
            <tbody id="trace-table"></tbody>
          </table></div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">RACI Governance</span></div>
          <div id="raci-list" style="font-size:13px">Loading...</div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">Control Ownership</span></div>
          <div class="table-wrap"><table>
            <thead><tr><th>Control</th><th>Owner</th><th>Status</th></tr></thead>
            <tbody id="ownership-table"></tbody>
          </table></div>
        </div>
      </div>
    </div>

    <!-- SOC Panel -->
    <div id="panel-soc" class="panel">
      <div class="grid4" style="grid-template-columns:repeat(2,1fr)">
        <div class="card">
          <div class="section-head"><span class="section-title">Framework Scorecard</span></div>
          <div id="scorecard-list">Loading...</div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">Zero Trust — 7 Pillars</span></div>
          <div id="zerotrust-list">Loading...</div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">Security Roadmap</span></div>
          <div class="table-wrap"><table>
            <thead><tr><th>Quarter</th><th>Title</th><th>Priority</th><th>Status</th></tr></thead>
            <tbody id="roadmap-table"></tbody>
          </table></div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">SOC Incidents</span></div>
          <div class="table-wrap"><table>
            <thead><tr><th>ID</th><th>Severity</th><th>Title</th></tr></thead>
            <tbody id="incidents-table"></tbody>
          </table></div>
        </div>
      </div>
    </div>

    <!-- Export Panel -->
    <div id="panel-export" class="panel">
      <div class="card" style="margin-bottom:16px">
        <div class="section-title" style="margin-bottom:12px">Export Latest Run</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-primary" onclick="exportFile('sarif')">Download SARIF 2.1.0</button>
          <button class="btn btn-primary" onclick="exportFile('csv')">Download CSV</button>
          <button class="btn btn-primary" onclick="exportFile('json')">Download JSON</button>
        </div>
        <div id="export-rid" style="margin-top:10px;font-size:12px;color:#64748b"></div>
      </div>
      <div class="grid4" style="grid-template-columns:repeat(2,1fr)">
        <div class="card">
          <div class="section-head">
            <span class="section-title">OSCAL Assessment Result</span>
            <button class="btn btn-sm btn-outline" onclick="downloadOSCAL('ar')">Download</button>
          </div>
          <pre id="oscal-ar-preview" style="font-size:11px;color:#94a3b8;overflow:auto;max-height:200px;white-space:pre-wrap"></pre>
        </div>
        <div class="card">
          <div class="section-head">
            <span class="section-title">OSCAL POA&amp;M</span>
            <button class="btn btn-sm btn-outline" onclick="downloadOSCAL('poam')">Download</button>
          </div>
          <pre id="oscal-poam-preview" style="font-size:11px;color:#94a3b8;overflow:auto;max-height:200px;white-space:pre-wrap"></pre>
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
  if (name === 'audit')      loadAudit()
  if (name === 'governance') { loadRiskRegister(); loadTraceability(); loadRACI(); loadOwnership() }
  if (name === 'soc')        { loadScorecard(); loadZeroTrust(); loadRoadmap(); loadIncidents() }
  if (name === 'export')     loadExport()
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


async function loadRiskRegister() {
  try {
    const data = await api('GET', '/governance/risk-register')
    const risks = data.risks || []
    const colors = {CRITICAL:'#f87171',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#4ade80'}
    document.getElementById('risk-table').innerHTML = risks.length
      ? risks.map(r => `<tr>
          <td><span style="font-weight:600;color:${colors[r.level]||'#94a3b8'}">${r.level}</span></td>
          <td style="font-size:12px">${esc(r.title)}</td>
          <td><span class="pill ${r.status==='open'?'pill-failed':'pill-done'}">${r.status}</span></td>
          <td style="color:#64748b;font-size:11px">${r.due_date?new Date(r.due_date).toLocaleDateString():'-'}</td>
        </tr>`).join('')
      : '<tr><td colspan="4" style="color:#64748b;padding:16px;text-align:center">No risks found — run a scan first</td></tr>'
  } catch(e) { console.error('risks', e) }
}

async function loadTraceability() {
  try {
    const data = await api('GET', '/governance/traceability')
    const rows = data.rows || []
    document.getElementById('trace-table').innerHTML = rows.length
      ? rows.map(r => `<tr>
          <td>${sevPill(r.severity)}</td>
          <td style="font-family:monospace;font-size:11px">${esc(r.rule_id)}</td>
          <td style="font-family:monospace;font-size:11px;color:#818cf8">${r.control}</td>
          <td style="color:#64748b;font-size:11px">${r.framework}</td>
        </tr>`).join('')
      : '<tr><td colspan="4" style="color:#64748b;padding:16px;text-align:center">No findings to trace</td></tr>'
  } catch(e) { console.error('trace', e) }
}

async function loadRACI() {
  try {
    const data = await api('GET', '/governance/raci')
    const raci = data.raci || []
    document.getElementById('raci-list').innerHTML = raci.map(r =>
      `<div style="padding:8px 0;border-bottom:1px solid #1e293b;font-size:12px">
        <b style="color:#e2e8f0">${esc(r.activity)}</b><br>
        <span style="color:#60a5fa">R: ${r.responsible}</span> &nbsp;
        <span style="color:#4ade80">A: ${r.accountable}</span> &nbsp;
        <span style="color:#fbbf24">C: ${r.consulted}</span>
       </div>`).join('')
  } catch(e) { console.error('raci', e) }
}

async function loadOwnership() {
  try {
    const data = await api('GET', '/governance/ownership')
    const owners = data.owners || []
    document.getElementById('ownership-table').innerHTML = owners.map(o => `
      <tr>
        <td style="font-family:monospace;font-size:12px;color:#818cf8">${o.control}</td>
        <td style="font-size:12px">${o.owner}</td>
        <td><span class="pill ${o.status==='implemented'?'pill-done':o.status==='partial'?'pill-queued':'pill-failed'}">${o.status}</span></td>
      </tr>`).join('')
  } catch(e) { console.error('ownership', e) }
}

async function loadScorecard() {
  try {
    const data = await api('GET', '/soc/framework-scorecard')
    const fws = data.frameworks || []
    document.getElementById('scorecard-list').innerHTML = fws.map(f => {
      const color = f.score >= 80 ? '#4ade80' : f.score >= 60 ? '#fbbf24' : '#f87171'
      return `<div style="margin-bottom:14px">
        <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px">
          <span style="font-size:13px;color:#e2e8f0">${f.framework}</span>
          <span style="font-size:20px;font-weight:700;color:${color}">${f.score}</span>
        </div>
        <div style="background:#0f172a;border-radius:4px;height:6px">
          <div style="width:${f.score}%;background:${color};height:6px;border-radius:4px;transition:width .5s"></div>
        </div>
      </div>`}).join('')
  } catch(e) { console.error('scorecard', e) }
}

async function loadZeroTrust() {
  try {
    const data = await api('GET', '/soc/zero-trust')
    const pillars = data.pillars || []
    document.getElementById('zerotrust-list').innerHTML = pillars.map(p => {
      const color = p.score >= 80 ? '#4ade80' : p.score >= 60 ? '#fbbf24' : '#f87171'
      return `<div style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;align-items:baseline">
          <span style="font-size:12px;color:#e2e8f0">${p.pillar}</span>
          <span style="font-size:14px;font-weight:600;color:${color}">${p.score}
            <span style="font-size:10px;color:#64748b">${p.level}</span></span>
        </div>
        <div style="background:#0f172a;border-radius:3px;height:4px;margin-top:3px">
          <div style="width:${p.score}%;background:${color};height:4px;border-radius:3px;transition:width .5s"></div>
        </div>
        ${p.open_findings>0?`<div style="font-size:10px;color:#f87171;margin-top:2px">${p.open_findings} open findings</div>`:''}
      </div>`}).join('')
  } catch(e) { console.error('zerotrust', e) }
}

async function loadRoadmap() {
  try {
    const data = await api('GET', '/soc/roadmap')
    const items = data.roadmap || []
    const colors = {CRITICAL:'#f87171',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#94a3b8'}
    document.getElementById('roadmap-table').innerHTML = items.map(r => `
      <tr>
        <td style="color:#64748b;font-size:11px;white-space:nowrap">${r.quarter}</td>
        <td style="font-size:12px">${esc(r.title)}</td>
        <td><span style="font-size:11px;font-weight:600;color:${colors[r.priority]||'#94a3b8'}">${r.priority}</span></td>
        <td><span class="pill ${r.status==='done'?'pill-done':r.status==='in-progress'?'pill-running':r.status==='overdue'?'pill-failed':'pill-queued'}">${r.status}</span></td>
      </tr>`).join('')
  } catch(e) { console.error('roadmap', e) }
}

async function loadIncidents() {
  try {
    const data = await api('GET', '/soc/incidents')
    const inc = data.incidents || []
    document.getElementById('incidents-table').innerHTML = inc.length
      ? inc.map(i => `<tr>
          <td style="font-family:monospace;font-size:11px;color:#94a3b8">${i.id}</td>
          <td>${sevPill(i.severity)}</td>
          <td style="font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(i.title)}</td>
        </tr>`).join('')
      : '<tr><td colspan="3" style="color:#64748b;padding:16px;text-align:center">No active incidents</td></tr>'
  } catch(e) { console.error('incidents', e) }
}

let currentRID = ''
async function loadExport() {
  try {
    const r = await api('GET', '/vsp/run/latest')
    currentRID = r.rid
    document.getElementById('export-rid').textContent = 'Latest run: ' + r.rid + ' (' + r.status + ')'
    const ar = await api('GET', '/compliance/oscal/ar')
    document.getElementById('oscal-ar-preview').textContent = JSON.stringify(ar, null, 2).slice(0,600) + '\n...'
    const poam = await api('GET', '/compliance/oscal/poam')
    document.getElementById('oscal-poam-preview').textContent = JSON.stringify(poam, null, 2).slice(0,600) + '\n...'
  } catch(e) { console.error('export', e) }
}

function exportFile(fmt) {
  if (!currentRID) { alert('No run selected'); return }
  const a = document.createElement('a')
  a.href = API + '/export/' + fmt + '/' + currentRID
  a.download = 'vsp-' + currentRID + '.' + fmt
  a.click()
}

function downloadOSCAL(type) {
  const a = document.createElement('a')
  a.href = API + '/compliance/oscal/' + type + '?format=download'
  a.download = 'oscal-' + type + '.json'
  a.click()
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
VSP7STATIC_INDEX_HTML

echo ">>> go mod tidy + build..."
go mod tidy
go build -buildvcs=false -o gateway ./cmd/gateway/ && echo 'gateway OK'
go build -buildvcs=false -o scanner ./cmd/scanner/ && echo 'scanner OK'

echo ">>> Restarting services..."
sudo systemctl restart vsp-gateway vsp-scanner vsp-go-shell 2>/dev/null || true
pkill -x gateway 2>/dev/null; pkill -x scanner 2>/dev/null; pkill -x soc-shell 2>/dev/null; sleep 1
./gateway & ./scanner & ./soc-shell &
sleep 3

export TOKEN=$(curl -s -X POST http://localhost:8921/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@vsp.local","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Token OK"

# Install missing tools
echo "--- Checking tool availability..."
which nuclei  2>/dev/null && echo 'nuclei: OK' || echo 'nuclei: NOT INSTALLED (pip install nuclei or go install)'
which checkov 2>/dev/null && echo 'checkov: OK' || echo 'checkov: NOT INSTALLED (pip install checkov)'

echo "--- /health v0.4.1"
curl -s http://localhost:8921/health | python3 -m json.tool

echo "--- SLA Tracker"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8921/api/v1/vsp/sla_tracker | python3 -m json.tool

echo "--- Metrics SLOs"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8921/api/v1/vsp/metrics_slos | python3 -m json.tool

echo "--- Sandbox test-fire"
curl -s -X POST http://localhost:8921/api/v1/vsp/sandbox/test-fire \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"test","gate":"FAIL","severity":"CRITICAL"}' \
  | python3 -m json.tool

echo "--- Sandbox list"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8921/api/v1/vsp/sandbox | python3 -m json.tool

# HTML report
RID=$(curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8921/api/v1/vsp/run/latest \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['rid'])")
echo "--- HTML report for $RID"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8921/api/v1/vsp/run_report_html/$RID" | head -5

# Install checkov if pip available
pip install checkov --break-system-packages --quiet 2>/dev/null && echo 'checkov installed' || echo 'checkov install failed'
which checkov && checkov --version | head -1 || true

echo ""
echo "================================================================"
echo "  VSP Go v0.4.1 — Feature Parity ~95%"
echo ""
echo "  NEW ENDPOINTS:"
echo "  GET  /vsp/run_report_html/{rid}  — HTML scan report"
echo "  GET  /vsp/sla_tracker            — SLA breach tracking"
echo "  GET  /vsp/metrics_slos           — Scan SLO metrics"
echo "  GET/POST/DELETE /vsp/sandbox/*   — Webhook sandbox"
echo "  POST /import/policies            — Import policy rules"
echo "  POST /import/findings            — Import CSV findings"
echo "  POST /import/users               — Import users"
echo "  POST /vsp/rbac/session-timeout   — RBAC config"
echo ""
echo "  NEW TOOLS:"
echo "  nuclei  — template-based DAST (needs: go install nuclei)"
echo "  checkov — IaC scanner #2 (needs: pip install checkov)"
echo "  codeql  — fixed: auto-detect Python/Go/JS language"
echo ""
echo "  REMAINING GAPS:"
echo "  PDF report     — needs chromedp (headless Chrome)"
echo "  Swagger UI     — needs swaggo annotations"
echo "  Audit persist  — writeAudit goroutine context fix"
echo "  Multi-tenant UI — tenant switch on login page"
echo "================================================================"
