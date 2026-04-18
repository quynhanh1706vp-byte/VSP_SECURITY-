package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

func main() {
	// ── Logger ────────────────────────────────────────────────
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// ── Config via viper ──────────────────────────────────────
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("database.url", "postgres://vsp:vsp@localhost:5432/vsp?sslmode=disable")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		log.Warn().Err(err).Msg("config file not found, using defaults + env")
	}

	// ── Database ──────────────────────────────────────────────
	dbURL := viper.GetString("database.url")
	if envDB := os.Getenv("DATABASE_URL"); envDB != "" {
		dbURL = envDB
	}
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open database")
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		log.Fatal().Err(err).Str("db_url", dbURL).Msg("database ping failed")
	}
	var dbName, dbUser string
	db.QueryRowContext(ctx, "SELECT current_database(), current_user").Scan(&dbName, &dbUser)
	var tableCount int
	db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pg_tables WHERE schemaname='public'").Scan(&tableCount)
	var hasRem bool
	db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='remediation_items')").Scan(&hasRem)
	log.Info().Str("db", dbName).Str("user", dbUser).Int("tables", tableCount).Bool("remediation_items_exists", hasRem).Str("url", dbURL).Msg("database connected")

	// ── Router ────────────────────────────────────────────────
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	// Timeout middleware - exempt SSE endpoint
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/events" {
				next.ServeHTTP(w, r)
				return
			}
			middleware.Timeout(60*time.Second)(next).ServeHTTP(w, r)
		})
	})
	r.Use(middleware.Compress(5, "text/html", "application/json", "text/css", "application/javascript"))
	r.Use(func(next http.Handler) http.Handler {
		return CSRFMiddleware(next)
	})

	// ── Static files ──────────────────────────────────────────
	staticDir := "./static"
	fs := http.FileServer(http.Dir(staticDir))

	// Serve /static/* (legacy)
	r.Handle("/static/*", http.StripPrefix("/static/", fs))

	// Serve panels/
	r.Handle("/panels/*", http.StripPrefix("/panels/", http.FileServer(http.Dir(staticDir+"/panels"))))

	// Serve tất cả file tĩnh ở root — fix 404 cho .js/.css/.html
	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		http.ServeFile(w, req, staticDir+req.URL.Path)
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, staticDir+"/index.html")
	})

	// ── API routes ────────────────────────────────────────────
	r.Route("/api/v1", func(r chi.Router) {

		// Auth
		r.Post("/auth/login", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Trả JWT stub hợp lệ — header.payload.sig (exp xa)
			token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbkB2c3AubG9jYWwiLCJlbWFpbCI6ImFkbWluQHZzcC5sb2NhbCIsInJvbGUiOiJhZG1pbiIsInRlbmFudF9pZCI6ImRlZmF1bHQiLCJleHAiOjk5OTk5OTk5OTl9.signature" //nolint:gosec // G101: dev stub token, not a real credential
			fmt.Fprintf(w, `{"ok":true,"token":%q,"email":"admin@vsp.local","role":"admin","tenant_id":"default"}`, token)
		})
		r.Post("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		})
		r.Post("/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbkB2c3AubG9jYWwiLCJlbWFpbCI6ImFkbWluQHZzcC5sb2NhbCIsInJvbGUiOiJhZG1pbiIsInRlbmFudF9pZCI6ImRlZmF1bHQiLCJleHAiOjk5OTk5OTk5OTl9.signature" //nolint:gosec // G101: dev stub token, not a real credential
			fmt.Fprintf(w, `{"ok":true,"token":%q}`, token)
		})
		r.Post("/auth/password/change", stubHandler("auth.password.change"))
		r.Post("/auth/mfa/setup", stubHandler("auth.mfa.setup"))
		r.Post("/auth/mfa/verify", stubHandler("auth.mfa.verify"))

		// VSP scan & runs
		r.Post("/vsp/run", stubHandler("vsp.run"))
		r.Get("/vsp/runs", HandleRunsIndexV2(db))
		r.Get("/vsp/runs/index", HandleRunsIndexV2(db))
		r.Get("/vsp/run/latest", HandleRunLatestV2(db))
		r.Get("/vsp/run/{rid}", HandleRunByRID(db))
		r.Get("/vsp/findings", HandleFindingsListReal(db))
		r.Get("/vsp/findings/summary", HandleFindingsSummary(db))

		// FULL_SOC
		r.Post("/vsp/run/full-soc", HandleFullSOCTriggerReal(db))
		r.Get("/vsp/runs/full-soc", HandleFullSOCList(db))

		// Remediation
		r.Patch("/remediation/{id}/status", HandleRemediationStatusV2(db))
		r.Post("/remediation/bulk-status", HandleRemediationBulkStatusV2(db))
		r.Post("/remediation/auto", HandleRemediationAuto(db))
		r.Get("/remediation/stats", HandleRemediationStatsReal(db))
		r.Get("/vsp/findings/by-tool", HandleFindingsByTool(db))
		r.Get("/vsp/run/{rid}/log", HandleRunLog(db))

		// Admin
		r.Get("/admin/users", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"users":[
				{"id":"u1","email":"admin@vsp.local","role":"admin","tenant_id":"default","status":"active","last_login":"2026-04-16T07:24:00Z","mfa_enabled":true},
				{"id":"u2","email":"analyst@vsp.local","role":"analyst","tenant_id":"default","status":"active","last_login":"2026-04-15T09:00:00Z","mfa_enabled":false},
				{"id":"u3","email":"cicd@vsp.local","role":"api","tenant_id":"default","status":"active","last_login":"2026-04-16T02:00:00Z","mfa_enabled":false},
				{"id":"u4","email":"sec-eng@vsp.local","role":"analyst","tenant_id":"default","status":"active","last_login":"2026-04-14T14:00:00Z","mfa_enabled":true},
				{"id":"u5","email":"viewer@vsp.local","role":"viewer","tenant_id":"default","status":"inactive","last_login":"2026-03-01T10:00:00Z","mfa_enabled":false}
			],"total":5}`))
		})
		r.Post("/admin/users", stubHandler("admin.users.create"))

		// Correlation & SIEM
		r.Get("/correlation/incidents", stubHandler("correlation.incidents"))

		// SW Inventory
		r.Get("/sw/inventory", stubHandler("sw.inventory"))
		r.Get("/sw/whitelist", stubHandler("sw.whitelist"))
		r.Get("/sw/blacklist", stubHandler("sw.blacklist"))
		r.Post("/sw/hash-check", stubHandler("sw.hash-check"))
		r.Post("/sw/policy", stubHandler("sw.policy"))
		r.Get("/sw/license-check", stubHandler("sw.license-check"))
		r.Post("/sw/report", stubHandler("sw.report"))
		r.Post("/sw/scan", stubHandler("sw.scan"))
		r.Get("/siem/webhooks", stubHandler("siem.webhooks.list"))
		r.Post("/siem/webhooks", stubHandler("siem.webhooks.create"))

		// Auth token (exempt CSRF)
		r.Post("/auth/token", stubHandler("auth.token"))

		// Schedules / CI-CD
		r.Get("/schedules", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schedules":[
				{"id":"sc1","name":"Daily production scan","mode":"SAST","profile":"STANDARD","cron":"0 2 * * *","src":"/home/test/Data/GOLANG_VSP","enabled":true,"next_run":"today 02:00","last_gate":"FAIL","last_status":"DONE","tags":["daily","production"]},
				{"id":"sc2","name":"IAC infrastructure check","mode":"IAC","profile":"FAST","cron":"0 6 * * *","src":"/home/test/Data/GOLANG_VSP","enabled":true,"next_run":"today 06:00","last_gate":"WARN","last_status":"DONE","tags":["infra","daily"]},
				{"id":"sc3","name":"Weekly deep scan","mode":"FULL","profile":"THOROUGH","cron":"0 3 * * 1","src":"/home/test/Data/GOLANG_VSP","enabled":true,"next_run":"Mon 03:00","last_gate":"FAIL","last_status":"DONE","tags":["weekly","thorough"]},
				{"id":"sc4","name":"Secrets scan (disabled)","mode":"SECRETS","profile":"FAST","cron":"0 12 * * *","src":"/home/test/Data/GOLANG_VSP","enabled":false,"next_run":"—","last_gate":"PASS","last_status":"DONE","tags":["secrets"]},
				{"id":"sc5","name":"SCA dependency audit","mode":"SCA","profile":"STANDARD","cron":"0 0 * * 0","src":"/home/test/Data/GOLANG_VSP","enabled":true,"next_run":"Sun 00:00","last_gate":"WARN","last_status":"DONE","tags":["deps","weekly"]}
			],"total":5}`))
		})
		r.Post("/schedules", stubHandler("schedules.create"))
		r.Put("/schedules/{id}", stubHandler("schedules.update"))
		r.Delete("/schedules/{id}", stubHandler("schedules.delete"))

		// VSP posture / gate / metrics
		r.Get("/vsp/posture/latest", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"score":30,"grade":"F","gate":"FAIL","critical":1,"high":80,"medium":147,"low":3,"total_findings":231}`))
		})
		r.Get("/vsp/gate/latest", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"gate":"FAIL","score":30,"threshold":70,"run_id":"latest"}`))
		})
		r.Get("/vsp/sla_tracker", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sla":[
				{"severity":"CRITICAL","sla_days":3,"open_count":1,"breach_count":0,"avg_age_days":1.2,"status":"green"},
				{"severity":"HIGH","sla_days":14,"open_count":80,"breach_count":2,"avg_age_days":8.4,"status":"yellow"},
				{"severity":"MEDIUM","sla_days":30,"open_count":139,"breach_count":0,"avg_age_days":12.1,"status":"green"},
				{"severity":"LOW","sla_days":90,"open_count":142,"breach_count":0,"avg_age_days":15.3,"status":"green"}
			]}`))
		})
		r.Get("/vsp/metrics_slos", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"mttr_critical":1.2,"mttr_high":5.4,"sla_breach_rate":0.04,"open_critical":1,"open_high":80}`))
		})

		// Audit
		r.Get("/audit/log", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"entries":[
				{"id":"1","seq":1,"action":"LOGIN","user":"admin@vsp.local","resource":"auth","ip":"127.0.0.1","detail":"Login from 127.0.0.1","created_at":"2026-04-16T07:24:00Z","level":"info"},
				{"id":"2","seq":2,"action":"SCAN_TRIGGERED","user":"admin@vsp.local","resource":"scan","ip":"127.0.0.1","detail":"FULL scan triggered","created_at":"2026-04-16T07:00:00Z","level":"info"},
				{"id":"3","seq":3,"action":"FINDING_UPDATED","user":"admin@vsp.local","resource":"findings","ip":"127.0.0.1","detail":"Finding marked resolved","created_at":"2026-04-15T14:00:00Z","level":"warn"},
				{"id":"4","seq":4,"action":"LOGIN","user":"cicd@vsp.local","resource":"auth","ip":"192.168.1.50","detail":"API token login","created_at":"2026-04-15T02:00:00Z","level":"info"},
				{"id":"5","seq":5,"action":"SCAN_COMPLETE","user":"system","resource":"scan","ip":"127.0.0.1","detail":"Daily scan complete — 104 findings","created_at":"2026-04-15T02:30:00Z","level":"info"}
			],"total":5}`))
		})
		r.Get("/audit/stats", stubHandler("audit.stats"))
		r.Get("/audit/monthly", stubHandler("audit.monthly"))
		r.Post("/audit/rotate", stubHandler("audit.rotate"))

		// Notifications
		r.Get("/notifications", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"notifications":[],"total":0,"unread":0}`))
		})

		// Compliance
		r.Get("/compliance/fedramp", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"score":82,"controls_pass":299,"controls_total":325,"status":"MODERATE"}`))
		})
		r.Get("/compliance/cmmc", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"level":2,"score":87,"practices_pass":96,"practices_total":110,"status":"IN_PROGRESS"}`))
		})
		r.Get("/compliance/oscal/{type}", stubHandler("compliance.oscal"))

		// SOC
		r.Get("/soc/framework-scorecard", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"frameworks":[
				{"name":"NIST CSF","score":78,"maturity":"Defined"},
				{"name":"FedRAMP","score":82,"maturity":"Managed"},
				{"name":"CMMC L2","score":87,"maturity":"Defined"},
				{"name":"Zero Trust","score":82,"maturity":"Advanced"}
			]}`))
		})
		r.Get("/soc/zero-trust", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"score":82,"pillars":{"identity":90,"device":78,"network":85,"application":80,"data":75}}`))
		})

		// Governance
		r.Get("/governance/raci", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"roles":["CISO","ISSO","DevSecOps","SOC","AO"],"matrix":[
				{"process":"Vulnerability Management","CISO":"A","ISSO":"R","DevSecOps":"R","SOC":"C","AO":"I"},
				{"process":"Incident Response","CISO":"A","ISSO":"R","DevSecOps":"C","SOC":"R","AO":"I"},
				{"process":"Change Management","CISO":"I","ISSO":"A","DevSecOps":"R","SOC":"C","AO":"A"},
				{"process":"Risk Assessment","CISO":"A","ISSO":"R","DevSecOps":"C","SOC":"C","AO":"A"},
				{"process":"Security Training","CISO":"A","ISSO":"R","DevSecOps":"I","SOC":"I","AO":"I"}
			]}`))
		})
		r.Get("/governance/risk-register", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"risks":[
				{"id":"R-001","rule_id":"CVE-2024-45337","title":"Unpatched CVE-2024-45337","level":"CRITICAL","likelihood":"HIGH","impact":"CRITICAL","score":9.1,"status":"open","owner":"DevSecOps","description":"PublicKeyCallback auth bypass in golang.org/x/crypto","mitigation":"Update to v0.31.0","due_date":"2026-04-30"},
				{"id":"R-002","rule_id":"CWE-798","title":"Hardcoded API key in .env","level":"HIGH","likelihood":"HIGH","impact":"HIGH","score":8.8,"status":"in_remediation","owner":"DevSecOps","description":"API key hardcoded in .env file","mitigation":"Move to secrets manager","due_date":"2026-05-01"},
				{"id":"R-003","rule_id":"CWE-307","title":"Missing rate limiting on auth","level":"MEDIUM","likelihood":"MEDIUM","impact":"MEDIUM","score":5.9,"status":"open","owner":"ISSO","description":"Auth endpoints vulnerable to brute force","mitigation":"Add rate limiting middleware","due_date":"2026-05-15"},
				{"id":"R-004","rule_id":"CWE-732","title":"S3 bucket public ACL","level":"HIGH","likelihood":"HIGH","impact":"HIGH","score":7.5,"status":"open","owner":"DevSecOps","description":"S3 bucket allows public read/write","mitigation":"Set ACL to private","due_date":"2026-04-25"}
			],"total":4}`))
		})
		r.Get("/governance/traceability", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[
				{"id":"t1","finding_id":"cve202445","control":"SI-2","framework":"NIST SP 800-53","requirement":"Flaw Remediation","status":"open","mapped_at":"2026-04-13"},
				{"id":"t2","finding_id":"a1b2c3d4","control":"IA-5","framework":"NIST SP 800-53","requirement":"Authenticator Management","status":"in_remediation","mapped_at":"2026-04-13"},
				{"id":"t3","finding_id":"f1234567","control":"SC-7","framework":"NIST SP 800-53","requirement":"Boundary Protection","status":"open","mapped_at":"2026-04-13"},
				{"id":"t4","finding_id":"g7654321","control":"IA-5","framework":"FedRAMP","requirement":"Token Management","status":"open","mapped_at":"2026-04-13"}
			],"total":4}`))
		})

		// Policy
		r.Get("/policy/rules", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"rules":[
				{"id":"r1","name":"Block Critical Findings","type":"built-in","active":true,"block_critical":true,"block_secrets":false,"max_high":-1,"min_score":0,"description":"Fail gate if any CRITICAL finding exists"},
				{"id":"r2","name":"Block Secrets","type":"built-in","active":true,"block_critical":false,"block_secrets":true,"max_high":-1,"min_score":0,"description":"Fail gate if secrets detected"},
				{"id":"r3","name":"Score Threshold","type":"custom","active":true,"block_critical":false,"block_secrets":false,"max_high":-1,"min_score":70,"description":"Warn if score below 70"},
				{"id":"r4","name":"High Findings Limit","type":"custom","active":false,"block_critical":false,"block_secrets":false,"max_high":50,"min_score":0,"description":"Warn if more than 50 HIGH findings"},
				{"id":"r5","name":"IaC Misconfig Block","type":"custom","active":false,"block_critical":false,"block_secrets":false,"max_high":-1,"min_score":0,"description":"Block on critical IaC misconfigurations"}
			],"total":5}`))
		})
		r.Post("/policy/evaluate", stubHandler("policy.evaluate"))
		r.Put("/policy/rules/{id}", stubHandler("policy.rules.update"))
		r.Delete("/policy/rules/{id}", stubHandler("policy.rules.delete"))

		// Logs
		r.Get("/logs/stats", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"total_events":48291,"online":3,"sources":[{"name":"syslog","status":"online","eps":142},{"name":"Windows Event","status":"online","eps":89},{"name":"CloudTrail","status":"online","eps":31}]}`))
		})
		// SSE endpoint
		r.Get("/events", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			// Gửi event connected
			fmt.Fprint(w, "data: {\"type\":\"connected\",\"status\":\"ok\"}\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			// Keepalive mỗi 15s
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-r.Context().Done():
					return
				case <-ticker.C:
					fmt.Fprint(w, ": keepalive\n\n")
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
				}
			}
		})

		// SOAR
		r.Get("/soar/runs", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"runs":[
				{"id":"run-001","playbook":"Gate FAIL Response","status":"completed","triggered_at":"2026-04-16T02:31:00Z","duration_s":12,"actions_taken":3},
				{"id":"run-002","playbook":"Critical Finding Alert","status":"completed","triggered_at":"2026-04-15T02:31:00Z","duration_s":8,"actions_taken":2}
			],"total":2}`))
		})

		// Correlation incidents
		r.Get("/correlation/incidents", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"incidents":[
				{"id":"INC-001","title":"CVE-2024-45337 detected during deploy","severity":"CRITICAL","status":"investigating","created_at":"2026-04-16T12:47:00Z","rule_name":"Critical CVE + deploy event"},
				{"id":"INC-002","title":"generic-api-key exposed in .env","severity":"CRITICAL","status":"open","created_at":"2026-04-16T11:18:00Z","rule_name":"Secret exposure"},
				{"id":"INC-003","title":"SSH brute force from 185.220.101.47","severity":"HIGH","status":"resolved","created_at":"2026-04-15T09:00:00Z","rule_name":"Port scan + brute force"}
			],"total":3}`))
		})

		// SBOM
		r.Get("/sbom/{rid}", stubHandler("sbom"))
		r.Get("/sbom/{rid}/diff", stubHandler("sbom.diff"))

		// Remediation - proxy từ remediations table
		r.Get("/remediation", HandleRemediationListReal(db))
		r.Get("/remediation/finding/{id}", stubHandler("remediation.finding"))

		// Reports / export
		r.Get("/vsp/tt13_report/{rid}", stubHandler("report.tt13"))
		r.Get("/vsp/tt13_report_pdf/{rid}", stubHandler("report.tt13.pdf"))
		r.Get("/vsp/run_report_pdf/{rid}", stubHandler("report.run.pdf"))
		r.Get("/reports/common_pdf", stubHandler("report.common"))
		r.Get("/vsp/executive_report_pdf/{rid}", stubHandler("report.executive"))
		r.Get("/export/{type}", stubHandler("export"))

		// POA&M
		r.Post("/poam/sync", stubHandler("poam.sync"))

		// Alerts / webhooks
		r.Get("/alerts/webhooks", stubHandler("alerts.webhooks"))
		r.Post("/alerts/webhooks", stubHandler("alerts.webhooks.create"))
		r.Post("/alerts/webhooks/test", stubHandler("alerts.webhooks.test"))
		r.Post("/alerts/notify", stubHandler("alerts.notify"))

		// Assets
		r.Get("/assets", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"assets":[
				{"id":"a1","name":"API Gateway","type":"server","ip":"10.0.1.10","os":"Ubuntu 22.04","criticality":"HIGH","status":"online","findings":23,"cves":3},
				{"id":"a2","name":"Auth Service","type":"server","ip":"10.0.1.11","os":"Ubuntu 22.04","criticality":"CRITICAL","status":"online","findings":15,"cves":2},
				{"id":"a3","name":"PostgreSQL DB","type":"database","ip":"10.0.1.20","os":"Ubuntu 22.04","criticality":"CRITICAL","status":"online","findings":5,"cves":1},
				{"id":"a4","name":"K8s Cluster","type":"infra","ip":"10.0.3.1","os":"Kubernetes 1.28","criticality":"HIGH","status":"online","findings":47,"cves":5},
				{"id":"a5","name":"CI/CD Pipeline","type":"devops","ip":"10.0.2.10","os":"GitHub Actions","criticality":"HIGH","status":"online","findings":8,"cves":1},
				{"id":"a6","name":"Redis Cache","type":"database","ip":"10.0.1.21","os":"Redis 7.2","criticality":"MEDIUM","status":"online","findings":2,"cves":0}
			],"total":6}`))
		})
		r.Get("/assets/{id}", stubHandler("assets.get"))
		r.Post("/assets", stubHandler("assets.create"))

		// Correlation rules
		r.Get("/correlation/rules", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"rules":[],"total":0}`))
		})
		r.Post("/correlation/rules", stubHandler("correlation.rules.create"))
		r.Get("/correlation/incidents/{id}", stubHandler("correlation.incident.get"))

		// Logs
		r.Get("/logs/sources", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sources":[{"id":"s1","name":"syslog","status":"online","eps":142,"lastEvent":"2s","last_event":"2026-04-16T17:48:00Z","format":"RFC5424","tags":["linux","auth"]},{"id":"s2","name":"Windows Event","status":"online","eps":89,"lastEvent":"3s","last_event":"2026-04-16T17:47:55Z","format":"EVTX","tags":["windows","security"]},{"id":"s3","name":"CloudTrail","status":"online","eps":31,"lastEvent":"5s","last_event":"2026-04-16T17:47:30Z","format":"JSON","tags":["aws","audit"]}],"total":3}`))
		})
		r.Get("/logs/sources/{id}", stubHandler("logs.source.get"))
		r.Post("/logs/sources", stubHandler("logs.source.create"))
		r.Get("/logs/hunt", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[
				{"id":"h1","ts":"2026-04-16T13:30:00Z","rule":"SSH brute force","src":"185.220.101.47","dst":"10.0.1.10","severity":"HIGH","count":847,"status":"active"},
				{"id":"h2","ts":"2026-04-16T12:00:00Z","rule":"Unusual login time","user":"cicd@vsp.local","src":"10.0.2.10","severity":"MEDIUM","count":3,"status":"reviewed"},
				{"id":"h3","ts":"2026-04-15T02:00:00Z","rule":"Large data transfer","src":"10.0.1.10","dst":"8.8.8.8","severity":"LOW","count":1,"status":"benign"}
			],"total":3}`))
		})
		r.Get("/logs/network-flow", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"flows":[
				{"src":"185.220.101.47","dst":"10.0.1.10","proto":"TCP","port":22,"bytes":"28.4MB","pkts":124000,"status":"suspicious","geo":"RU","asn":"AS1337"},
				{"src":"10.0.1.11","dst":"0.0.0.0","proto":"TCP","port":443,"bytes":"1.2GB","pkts":2100000,"status":"ok","geo":"—","asn":"—"},
				{"src":"10.0.1.10","dst":"10.0.1.20","proto":"TCP","port":5432,"bytes":"512MB","pkts":891000,"status":"ok","geo":"—","asn":"—"},
				{"src":"45.142.212.100","dst":"10.0.1.10","proto":"TCP","port":22,"bytes":"12.1MB","pkts":48000,"status":"suspicious","geo":"NL","asn":"AS4242"},
				{"src":"10.0.3.1","dst":"10.0.1.10","proto":"TCP","port":8080,"bytes":"156MB","pkts":312000,"status":"ok","geo":"—","asn":"—"}
			],"total":5}`))
		})

		// SOAR
		r.Get("/soar/playbooks", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"playbooks":[{"id":"pb1","name":"Gate FAIL Response","trigger":"gate_fail","status":"active"},{"id":"pb2","name":"Critical Finding Alert","trigger":"critical_finding","status":"active"}],"total":2}`))
		})
		r.Post("/soar/playbooks/{id}", stubHandler("soar.playbook.run"))
		r.Post("/soar/trigger", stubHandler("soar.trigger"))

		// Threat Intel
		r.Get("/ti/iocs", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"iocs":[
				{"id":"i1","type":"CVE","val":"CVE-2024-45337","value":"CVE-2024-45337","severity":"CRITICAL","feed":"NVD","matched":true,"context":"PublicKeyCallback auth bypass CVSS 9.1","mitre":["T1190","T1203"]},
				{"id":"i2","type":"IP","val":"185.220.101.47","value":"185.220.101.47","severity":"HIGH","feed":"AbuseIPDB","matched":true,"context":"Tor exit node abuse confidence 94%","mitre":["T1090"]},
				{"id":"i3","type":"IP","val":"45.142.212.100","value":"45.142.212.100","severity":"HIGH","feed":"AbuseIPDB","matched":true,"context":"SSH brute force origin","mitre":["T1110"]},
				{"id":"i4","type":"CVE","val":"CVE-2025-22869","value":"CVE-2025-22869","severity":"HIGH","feed":"NVD","matched":true,"context":"DoS golang.org/x/crypto CVSS 8.7","mitre":["T1190"]},
				{"id":"i5","type":"HASH","val":"a3f8c1d9e2b4","value":"a3f8c1d9e2b4","severity":"HIGH","feed":"OTX","matched":false,"context":"Known malicious build artifact","mitre":["T1195"]}
			],"total":5}`))
		})
		r.Get("/ti/feeds", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"feeds":[{"id":"f1","name":"NVD CVE","status":"active"},{"id":"f2","name":"AbuseIPDB","status":"active"},{"id":"f3","name":"VNCERT","status":"active"}],"total":3}`))
		})
		r.Post("/ti/feeds/sync", stubHandler("ti.feeds.sync"))
		r.Get("/ti/matches", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"matches":[],"total":0}`))
		})

		// UEBA
		r.Get("/ueba/baseline", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ready","users":[
				{"user":"admin@vsp.local","risk_score":15,"anomalies":0,"last_seen":"2026-04-16T07:24:00Z","baseline_established":true,"alerts":[]},
				{"user":"cicd@vsp.local","risk_score":8,"anomalies":1,"last_seen":"2026-04-16T02:00:00Z","baseline_established":true,"alerts":["Unusual hour login"]},
				{"user":"analyst@vsp.local","risk_score":5,"anomalies":0,"last_seen":"2026-04-15T09:00:00Z","baseline_established":true,"alerts":[]},
				{"user":"sec-eng@vsp.local","risk_score":12,"anomalies":2,"last_seen":"2026-04-14T14:00:00Z","baseline_established":true,"alerts":["Access from new IP","Multiple failed logins"]}
			],"total":4,"high_risk":0,"medium_risk":1}`))
		})
		r.Post("/ueba/analyze", stubHandler("ueba.analyze"))

		// Vulns
		r.Get("/vulns/top-cves", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"cves":[
				{"cve":"CVE-2024-45337","cvss":9.1,"epss":0.72,"kev":true,"severity":"CRITICAL","package":"golang.org/x/crypto","version":"v0.28.0","fixed":"v0.31.0","count":12},
				{"cve":"CVE-2025-22869","cvss":8.7,"epss":0.41,"kev":false,"severity":"CRITICAL","package":"golang.org/x/crypto","version":"v0.28.0","fixed":"v0.35.0","count":8},
				{"cve":"CVE-2025-30204","cvss":7.5,"epss":0.33,"kev":false,"severity":"HIGH","package":"golang-jwt/jwt","version":"v4.5.0","fixed":"v4.5.1","count":5},
				{"cve":"CVE-2024-21626","cvss":8.6,"epss":0.61,"kev":true,"severity":"CRITICAL","package":"runc","version":"v1.1.0","fixed":"v1.1.12","count":3},
				{"cve":"CVE-2024-24790","cvss":7.3,"epss":0.12,"kev":false,"severity":"HIGH","package":"stdlib","version":"go1.21","fixed":"go1.21.11","count":9}
			],"total":5}`))
		})
		r.Get("/vulns/by-tool", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tools":[
				{"tool":"kics","critical":1,"high":20,"medium":45,"low":12,"total":78},
				{"tool":"trivy","critical":3,"high":8,"medium":15,"low":4,"total":30},
				{"tool":"gitleaks","critical":3,"high":0,"medium":0,"low":0,"total":3},
				{"tool":"checkov","critical":0,"high":13,"medium":22,"low":8,"total":43},
				{"tool":"semgrep","critical":0,"high":5,"medium":18,"low":6,"total":29},
				{"tool":"gosec","critical":0,"high":3,"medium":8,"low":2,"total":13}
			]}`))
		})
		r.Get("/vulns/trend", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"trend":[
				{"date":"2026-04-10","critical":3,"high":25,"medium":45},
				{"date":"2026-04-11","critical":3,"high":28,"medium":48},
				{"date":"2026-04-12","critical":5,"high":32,"medium":52},
				{"date":"2026-04-13","critical":5,"high":30,"medium":50},
				{"date":"2026-04-14","critical":4,"high":27,"medium":47},
				{"date":"2026-04-15","critical":3,"high":24,"medium":44},
				{"date":"2026-04-16","critical":3,"high":23,"medium":42}
			]}`))
		})

		// AI
		r.Post("/ai/analyze", stubHandler("ai.analyze"))

		// SIEM reports
		r.Get("/siem/report.pdf", stubHandler("siem.report.pdf"))
		r.Get("/siem/report.xlsx", stubHandler("siem.report.xlsx"))

		// Admin users
		r.Get("/admin/users/{id}", stubHandler("admin.users.get"))
		r.Put("/admin/users/{id}", stubHandler("admin.users.update"))
		r.Delete("/admin/users/{id}", stubHandler("admin.users.delete"))

		// Settings health check
		r.Get("/settings/dast-targets", stubHandler("settings.dast-targets"))
		r.Post("/settings/dast-targets", stubHandler("settings.dast-targets.save"))
		r.Get("/settings/tools", stubHandler("settings.tools"))
		r.Post("/settings/tools", stubHandler("settings.tools.save"))
	})

	// P4 Compliance API — xem p4_routes.go
	RegisterP4RoutesReal(r, db)

	// P4 route — vsp_upgrade_v100.js redirect tới đây
	r.Get("/p4", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/p4_compliance.html")
	})
	r.Get("/p4/*", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/p4_compliance.html")
	})

	// Health check
	// Proxy /api/v1/* và /api/p4/* → gateway:8921 (single auth source of truth)
	gwTarget, _ := url.Parse("http://127.0.0.1:8921")
	gwProxy := httputil.NewSingleHostReverseProxy(gwTarget)
	r.HandleFunc("/api/v1/*", func(w http.ResponseWriter, r *http.Request) {
		r.Host = gwTarget.Host
		gwProxy.ServeHTTP(w, r)
	})
	r.HandleFunc("/api/p4/*", func(w http.ResponseWriter, r *http.Request) {
		r.Host = gwTarget.Host
		gwProxy.ServeHTTP(w, r)
	})
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"VSP Security Platform","version":"v0.10.0"}`))
	})

	// ── Server ────────────────────────────────────────────────
	addr := fmt.Sprintf("%s:%s", viper.GetString("server.host"), viper.GetString("server.port"))
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // 0 = no timeout, needed for SSE
		IdleTimeout:  0, // 0 = no timeout, needed for SSE
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Info().Str("addr", addr).Msg("VSP platform starting")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	log.Info().Msg("shutting down...")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Error().Err(err).Msg("forced shutdown")
	}
	_ = db.Close()
	log.Info().Msg("bye")
}

func stubHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"stub":%q,"note":"wire real handler"}`, name)
	}
}

func init() {}
