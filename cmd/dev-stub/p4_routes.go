//go:build devstub
// +build devstub

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

func RegisterP4Routes(r chi.Router, db *sql.DB) {
	r.Route("/api/p4", func(r chi.Router) {

		// ── Overview ──────────────────────────────────────────
		r.Get("/pipeline/latest", p4PipelineLatest)
		r.Get("/pipeline/drift", p4PipelineDrift)
		r.Get("/pipeline/schedules", p4PipelineSchedules)
		r.Post("/pipeline/trigger", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, `{"ok":true,"rid":"PIPE_`+time.Now().Format("20060102_150405")+`","status":"queued"}`)
		})

		// ── RMF / ATO ─────────────────────────────────────────
		r.Get("/rmf", p4RMF)
		r.Get("/rmf/conmon", p4RMFConmon)
		r.Get("/rmf/ato-letter", p4ATOLetter)
		r.Post("/rmf/task", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, `{"ok":true}`)
		})

		// ── Zero Trust ────────────────────────────────────────
		r.Get("/zt/status", p4ZTStatus)
		r.Get("/zt/microseg", p4ZTMicroseg)
		r.Get("/zt/rasp", p4ZTRasp)

		// ── ATO Expiry ────────────────────────────────────────
		r.Get("/ato/expiry", p4ATOExpiry)

		// ── SBOM ──────────────────────────────────────────────
		r.Get("/sbom/view", stubHandler("p4.sbom.view"))
		r.Get("/sbom/view-db", p4SBOMViewDB)

		// ── VN Standards ──────────────────────────────────────
		r.Get("/vn-standards", p4VNStandards)
		r.Post("/vn-standards/update", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, `{"ok":true}`)
		})

		// ── Findings sync ─────────────────────────────────────
		r.Get("/findings/sync", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, `{"ok":true,"synced":104}`)
		})

		// ── OSCAL ─────────────────────────────────────────────
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, `{"status":"ok","p4":"operational"}`)
		})
		r.Get("/alerts/history", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, `{"alerts":[],"total":0}`)
		})
		r.Post("/alerts/test", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, `{"ok":true,"message":"Test alert sent"}`)
		})
		r.Get("/conmon/report", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, `{"status":"ok","report_url":"/api/p4/conmon/report.pdf"}`)
		})
		r.Get("/sbom/view", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, `{"components":[
				{"id":"c1","name":"golang.org/x/crypto","version":"v0.28.0","type":"library","license":"BSD-3-Clause","supplier":"Google","cves":["CVE-2024-45337","CVE-2025-22869"],"severity":"CRITICAL","fixable":true,"fixed_version":"v0.31.0"},
				{"id":"c2","name":"github.com/golang-jwt/jwt","version":"v4.5.0","type":"library","license":"MIT","supplier":"OSS","cves":["CVE-2025-30204"],"severity":"HIGH","fixable":true,"fixed_version":"v4.5.1"},
				{"id":"c3","name":"github.com/go-chi/chi","version":"v5.0.11","type":"library","license":"MIT","supplier":"OSS","cves":[],"severity":"NONE","fixable":false,"fixed_version":""},
				{"id":"c4","name":"github.com/jackc/pgx","version":"v5.5.5","type":"library","license":"MIT","supplier":"OSS","cves":[],"severity":"NONE","fixable":false,"fixed_version":""},
				{"id":"c5","name":"github.com/spf13/viper","version":"v1.18.2","type":"library","license":"MIT","supplier":"OSS","cves":[],"severity":"NONE","fixable":false,"fixed_version":""},
				{"id":"c6","name":"go","version":"1.21.0","type":"runtime","license":"BSD-3-Clause","supplier":"Google","cves":["CVE-2024-24790"],"severity":"HIGH","fixable":true,"fixed_version":"1.21.11"}
			],"total":6,"critical":1,"high":2,"medium":0,"low":0,"clean":3}`)
		})
		r.Get("/vn-standards", p4VNStandards)
		r.Post("/vn-standards/update", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, `{"ok":true}`)
		})
		r.Get("/oscal/ssp", func(w http.ResponseWriter, r *http.Request) {
			jsonOK(w, `{"ok":true,"format":"OSCAL","version":"1.0.4"}`)
		})
	})
}

// ── Handlers ──────────────────────────────────────────────────

func p4PipelineLatest(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `{
		"id":"pipe-001","status":"done","score":72,"gate":"WARN",
		"trigger_type":"scheduled","branch":"main",
		"summary":{
			"CRITICAL":1,"HIGH":23,"MEDIUM":147,"LOW":12,
			"SCORE":72,"score":72,
			"pass":21,"warn":3,"fail":1,
			"frameworks":{
				"FedRAMP":{"percent":82,"pass":22,"total":24,"delta":2.1},
				"CMMC":   {"percent":85,"pass":14,"total":16,"delta":1.5},
				"NIST":   {"percent":78,"pass":312,"total":400,"delta":-0.5}
			}
		},
		"tests":[
			{"name":"SAST scan","status":"pass","duration":"4m12s"},
			{"name":"SCA deps", "status":"warn","duration":"1m08s"},
			{"name":"Secrets",  "status":"pass","duration":"0m22s"},
			{"name":"IaC check","status":"fail","duration":"2m44s"}
		],
		"schedules":[]
	}`)
}

func p4PipelineDrift(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `[
		{"ts":"2026-04-15T02:00:00Z","type":"config_change","resource":"network.tf","detail":"Security group ingress rule changed","reverted":false,"control":"CM-6"},
		{"ts":"2026-04-14T14:22:00Z","type":"new_finding","resource":"go.mod","detail":"CVE-2024-45337 introduced","reverted":false,"control":"SI-2"},
		{"ts":"2026-04-13T09:11:00Z","type":"remediation","resource":"auth/middleware.go","detail":"JWT secret moved to env var","reverted":true,"control":"IA-5"}
	]`)
}

func p4PipelineSchedules(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `[
		{"id":"s1","name":"Daily FULL scan","cron":"0 2 * * *","mode":"FULL","enabled":true,"last_run":"2026-04-16T02:00:00Z","next_run":"2026-04-17T02:00:00Z"},
		{"id":"s2","name":"Weekly deep IAC","cron":"0 3 * * 1","mode":"IAC","enabled":true,"last_run":"2026-04-14T03:00:00Z","next_run":"2026-04-21T03:00:00Z"},
		{"id":"s3","name":"Monthly SCA full","cron":"0 4 1 * *","mode":"SCA","enabled":true,"last_run":"2026-04-01T04:00:00Z","next_run":"2026-05-01T04:00:00Z"}
	]`)
}

func p4RMF(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `{
		"ato_status":"ATO_ACTIVE",
		"score":92,
		"rmf_steps":[
			{"id":1,"name":"Categorize","status":"complete","owner":"CISO","description":"System categorization per FIPS 199","tasks":[
				{"id":"1a","name":"Define system boundary","status":"done","reference":"SP 800-18","artifact":"SSP-v2.1.pdf"},
				{"id":"1b","name":"Assign security category","status":"done","reference":"FIPS 199","artifact":""}
			]},
			{"id":2,"name":"Select","status":"complete","owner":"ISSO","description":"Select baseline controls","tasks":[
				{"id":"2a","name":"Select control baseline","status":"done","reference":"SP 800-53","artifact":"SSP-v2.1.pdf"},
				{"id":"2b","name":"Apply tailoring","status":"done","reference":"SP 800-53B","artifact":""}
			]},
			{"id":3,"name":"Implement","status":"complete","owner":"Dev Team","description":"Implement security controls","tasks":[
				{"id":"3a","name":"Implement AC controls","status":"done","reference":"AC-2","artifact":""},
				{"id":"3b","name":"Implement AU controls","status":"done","reference":"AU-2","artifact":""}
			]},
			{"id":4,"name":"Assess","status":"in_progress","owner":"3PAO","description":"Assess control effectiveness","tasks":[
				{"id":"4a","name":"Develop SAP","status":"done","reference":"SP 800-53A","artifact":"SAP-v1.0.pdf"},
				{"id":"4b","name":"Conduct assessment","status":"open","reference":"SP 800-53A","artifact":""}
			]},
			{"id":5,"name":"Authorize","status":"pending","owner":"AO","description":"Authorization decision","tasks":[
				{"id":"5a","name":"Compile security package","status":"open","reference":"SP 800-37","artifact":""},
				{"id":"5b","name":"AO review and decision","status":"open","reference":"SP 800-37","artifact":""}
			]},
			{"id":6,"name":"Monitor","status":"in_progress","owner":"SOC","description":"Continuous monitoring","tasks":[
				{"id":"6a","name":"Define ConMon strategy","status":"done","reference":"SP 800-137","artifact":"ConMon-Plan.pdf"},
				{"id":"6b","name":"Implement automated monitoring","status":"done","reference":"CA-7","artifact":""}
			]}
		],
		"poam_items":[
			{"id":"POAM-001","control_id":"AC-2","weakness_name":"Excessive privileged accounts","severity":"HIGH","status":"in_remediation","mitigation_plan":"Implement PAM solution and quarterly access reviews","scheduled_completion":"2026-06-30","cwe_id":"CWE-250"},
			{"id":"POAM-002","control_id":"SI-2","weakness_name":"Unpatched CVE-2024-45337","severity":"CRITICAL","status":"open","mitigation_plan":"Update golang.org/x/crypto to v0.31.0","scheduled_completion":"2026-04-30","cwe_id":"CWE-287"},
			{"id":"POAM-003","control_id":"SC-8","weakness_name":"Missing rate limiting on auth endpoints","severity":"MEDIUM","status":"open","mitigation_plan":"Add rate limiting middleware on /api/auth/*","scheduled_completion":"2026-05-15","cwe_id":"CWE-307"}
		],
		"artifacts":[
			{"type":"SSP","name":"System Security Plan","version":"2.1","size_kb":284,"status":"approved"},
			{"type":"SAP","name":"Security Assessment Plan","version":"1.0","size_kb":142,"status":"approved"},
			{"type":"SAR","name":"Security Assessment Report","version":"0.9","size_kb":198,"status":"review"},
			{"type":"POAM","name":"Plan of Action & Milestones","version":"3.2","size_kb":87,"status":"approved"}
		]
	}`)
}

func p4RMFConmon(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `{"activities":[
		{"ts":"2026-04-16T02:00:00Z","type":"scan","detail":"Daily FULL scan completed — 104 findings","status":"done"},
		{"ts":"2026-04-15T02:00:00Z","type":"scan","detail":"Daily FULL scan — 97 findings","status":"done"},
		{"ts":"2026-04-14T08:00:00Z","type":"poam_update","detail":"POAM-001 status updated to in_remediation","status":"info"},
		{"ts":"2026-04-13T00:00:00Z","type":"report","detail":"Monthly ConMon report generated","status":"done"}
	]}`)
}

func p4ATOLetter(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `{
		"system_name":"VSP Security Platform",
		"system_id":"VSP-DOD-2025-001",
		"ao":"CISO / Designated Authorizing Authority",
		"decision":"AUTHORIZE TO OPERATE",
		"effective":"2025-04-16",
		"expiry":"2027-04-16",
		"conditions":["Maintain POA&M remediation schedule","Submit monthly ConMon reports","Notify AO within 72h of significant changes"],
		"body":"This Authorization to Operate (ATO) is granted for the VSP Security Platform system. The system has been assessed and found to be operating within acceptable risk tolerances."
	}`)
}

func p4ZTStatus(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `{
		"score":82,
		"p4_readiness":94,
		"pillars":{
			"identity":    {"name":"Identity",    "score":90,"target":85},
			"device":      {"name":"Device",      "score":78,"target":85},
			"network":     {"name":"Network",     "score":85,"target":85},
			"application": {"name":"Application", "score":80,"target":85,"capabilities":[
				{"id":"AC-2.1","name":"App-level authorization","description":"RBAC enforced at API layer","level":"Advanced","status":"implemented","score":4,"max_score":5},
				{"id":"AC-2.2","name":"Session management","description":"JWT with short expiry","level":"Optimal","status":"implemented","score":5,"max_score":5},
				{"id":"AC-2.3","name":"Input validation","description":"Request validation middleware","level":"Advanced","status":"partial","score":3,"max_score":5},
				{"id":"AC-2.4","name":"Rate limiting","description":"Auth endpoint protection","level":"Traditional","status":"planned","score":1,"max_score":5}
			]},
			"data":        {"name":"Data",        "score":75,"target":85},
			"visibility":  {"name":"Visibility",  "score":88,"target":85},
			"automation":  {"name":"Automation",  "score":72,"target":85}
		},
		"capabilities":[
			{"name":"MFA enforcement","pillar":"identity","score":95,"status":"pass"},
			{"name":"Device compliance","pillar":"device","score":78,"status":"warn"},
			{"name":"Micro-segmentation","pillar":"network","score":82,"status":"warn"},
			{"name":"App-level authz","pillar":"application","score":88,"status":"pass"}
		]
	}`)
}

func p4ZTMicroseg(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `[
		{"id":"r1","name":"Web to App","source":"10.0.1.0/24","destination":"10.0.2.0/24","port":443,"action":"allow","mtls":true,"hit_count":142820},
		{"id":"r2","name":"Block DB public","source":"0.0.0.0/0","destination":"10.0.1.20","port":5432,"action":"deny","mtls":false,"hit_count":47},
		{"id":"r3","name":"K8s to App","source":"10.0.3.0/24","destination":"10.0.1.10","port":8080,"action":"allow","mtls":true,"hit_count":31204},
		{"id":"r4","name":"Block SSH ext","source":"0.0.0.0/0","destination":"10.0.0.0/8","port":22,"action":"deny","mtls":false,"hit_count":892}
	]`)
}

func p4ZTRasp(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `[
		{"ts":"2026-04-16T13:30:00Z","severity":"HIGH","type":"sql_injection","detail":"SQL injection attempt blocked","src_ip":"185.220.101.47","action":"blocked"},
		{"ts":"2026-04-16T12:14:00Z","severity":"MEDIUM","type":"path_traversal","detail":"Path traversal on /api/files","src_ip":"45.142.212.100","action":"blocked"},
		{"ts":"2026-04-16T10:02:00Z","severity":"CRITICAL","type":"auth_bypass","detail":"Auth bypass attempt on /api/admin","src_ip":"45.142.212.100","action":"blocked"},
		{"ts":"2026-04-16T09:45:00Z","severity":"LOW","type":"rate_limit","detail":"Rate limit on /api/auth/login","src_ip":"10.0.1.55","action":"throttled"}
	]`)
}

func p4ATOExpiry(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `{
		"expiration_date":"2027-04-16",
		"ato_expires":"2027-04-16",
		"days_remaining":365,
		"expiry_level":"ok",
		"status":"active",
		"review_due":"2026-10-16",
		"renewal_checklist":[
			{"task":"Schedule 3PAO assessment","done":false,"due_weeks_before_expiry":52},
			{"task":"Update SSP documentation","done":true,"due_weeks_before_expiry":26},
			{"task":"ConMon annual review","done":false,"due_weeks_before_expiry":12},
			{"task":"POA&M closure review","done":false,"due_weeks_before_expiry":8}
		],
		"milestones":[
			{"date":"2026-10-16","label":"6-month review","status":"upcoming"},
			{"date":"2027-01-16","label":"90-day notice","status":"upcoming"},
			{"date":"2027-04-16","label":"ATO expiry","status":"upcoming"}
		]
	}`)
}

func p4SBOMViewDB(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `{
		"total_components":47,"critical":2,"high":5,"medium":8,"clean":32,
		"ntia_compliance_pct":94.2,
		"last_scan":"2026-04-16T02:00:00Z",
		"policy_violations":["golang.org/x/crypto outdated - CVE-2024-45337"],
		"frameworks":["CycloneDX 1.4","SPDX 2.3","NTIA Minimum Elements"],
		"components":[
			{"name":"golang.org/x/crypto","version":"v0.28.0","type":"library","license":"BSD-3-Clause","cves":2,"severity":"CRITICAL","ntia_compliant":true},
			{"name":"github.com/go-chi/chi","version":"v5.2.5","type":"library","license":"MIT","cves":0,"severity":"NONE","ntia_compliant":true},
			{"name":"github.com/jackc/pgx","version":"v5.7.1","type":"library","license":"MIT","cves":0,"severity":"NONE","ntia_compliant":true},
			{"name":"github.com/rs/zerolog","version":"v1.33.0","type":"library","license":"MIT","cves":0,"severity":"NONE","ntia_compliant":true},
			{"name":"github.com/spf13/viper","version":"v1.19.0","type":"library","license":"MIT","cves":0,"severity":"NONE","ntia_compliant":true},
			{"name":"golang.org/x/net","version":"v0.35.0","type":"library","license":"BSD-3-Clause","cves":1,"severity":"HIGH","ntia_compliant":true},
			{"name":"python","version":"3.10.12","type":"runtime","license":"PSF-2.0","cves":1,"severity":"MEDIUM","ntia_compliant":true}
		]
	}`)
}

func p4VNStandards(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, `{"standards":[
		{"id":"TT17-2017","name":"Thông tư 17/2017/TT-BTTTT","framework":"VN_GOV","status":"passed","score":88,"controls_total":45,"controls_pass":40,"last_assessed":"2026-04-01"},
		{"id":"TCVN-11943","name":"TCVN 11943:2017 ISO 27001","framework":"VN_ISO27001","status":"partial","score":74,"controls_total":114,"controls_pass":84,"last_assessed":"2026-04-01"},
		{"id":"BKAV-SCORE","name":"BKAV Security Score","framework":"VN_SOC","status":"passed","score":91,"controls_total":30,"controls_pass":27,"last_assessed":"2026-04-10"},
		{"id":"VIETTEL-SOC","name":"Viettel SOC Baseline","framework":"VN_SOC","status":"passed","score":85,"controls_total":25,"controls_pass":21,"last_assessed":"2026-04-10"},
		{"id":"ND13-2023","name":"Nghị định 13/2023/NĐ-CP","framework":"VN_LAW","status":"partial","score":70,"controls_total":60,"controls_pass":42,"last_assessed":"2026-03-15"}
	]}`)
}

func jsonOK(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, body)
}

// Ensure db param không unused nếu chưa dùng
var _ = (*sql.DB)(nil)
var _ = json.Marshal
