// cmd/siem-seed/main.go
// Seed SIEM data: correlation rules, IOCs từ findings, log sources mẫu
// Usage: go run ./cmd/siem-seed/
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/viper"
	"github.com/vsp/platform/internal/store"
)

func main() {
	viper.SetDefault("database.url", "postgres://vsp:vsp@localhost:5432/vsp_go")
	viper.AutomaticEnv()
	ctx := context.Background()
	db, err := store.New(ctx, viper.GetString("database.url"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	var tenantID string
	db.Pool().QueryRow(ctx, `SELECT id FROM tenants WHERE slug='default' LIMIT 1`).Scan(&tenantID)
	if tenantID == "" {
		fmt.Fprintln(os.Stderr, "default tenant not found")
		os.Exit(1)
	}
	fmt.Printf("Seeding tenant: %s\n", tenantID)

	// ── 1. Correlation rules ──────────────────────────────────
	type rule struct{ name, sources, cond, sev string; win int }
	rules := []rule{
		{"Gate FAIL + secrets in window",    `["scan","git"]`,          "gate=FAIL AND tool=gitleaks",          "CRITICAL", 5},
		{"CVE critical + deploy event",      `["scan","infra"]`,        "severity=CRITICAL AND event=deploy",   "CRITICAL", 10},
		{"Repeated auth fail + scan FAIL",   `["auth","scan"]`,         "auth.fail_count>3 AND gate=FAIL",      "HIGH",     15},
		{"SBOM drift detected",              `["scan","git"]`,          "sbom.diff>5 AND branch=main",          "HIGH",     30},
		{"Score drop >20 in 1h",             `["scan"]`,                "score_delta<-20",                      "MEDIUM",   60},
		{"New critical + open PR",           `["scan","git"]`,          "severity=CRITICAL AND pr.state=open",  "HIGH",     20},
		{"SLA breach + no assignee",         `["sla","remediation"]`,   "sla.status=breach AND assignee=null",  "MEDIUM",   1440},
	}
	ruleCount := 0
	for _, r := range rules {
		var src []string
		json.Unmarshal([]byte(r.sources), &src)
		_, err := db.Pool().Exec(ctx, `
			INSERT INTO correlation_rules
				(tenant_id, name, sources, window_min, severity, condition_expr, enabled)
			VALUES ($1,$2,$3,$4,$5,$6,true)
			ON CONFLICT DO NOTHING`,
			tenantID, r.name, src, r.win, r.sev, r.cond)
		if err == nil { ruleCount++ }
	}
	fmt.Printf("✓  %d correlation rules seeded\n", ruleCount)

	// ── 2. Log sources ────────────────────────────────────────
	type src struct{ name, host, proto, format string; port int; tags []string }
	sources := []src{
		{"Linux syslog (prod)",  "10.0.1.10",   "syslog-udp", "syslog-rfc3164", 514,  []string{"linux","auth","prod"}},
		{"Nginx access log",     "10.0.1.11",   "syslog-tcp", "json-raw",       514,  []string{"web","nginx","prod"}},
		{"AWS CloudTrail",       "s3://logs",   "s3",         "aws-cloudtrail",  0,   []string{"aws","cloudtrail"}},
		{"Firewall (Palo Alto)", "10.0.2.1",    "syslog-tls", "cef-v25",        6514, []string{"firewall","network"}},
		{"VSP scan engine",      "127.0.0.1",   "http-json",  "json-raw",       8922, []string{"vsp","scan"}},
		{"GitHub audit log",     "api.github",  "http-json",  "json-raw",       443,  []string{"git","audit"}},
		{"Kubernetes events",    "10.0.3.1",    "agent",      "json-raw",       8514, []string{"k8s","infra"}},
	}
	srcCount := 0
	for _, s := range sources {
		_, err := db.Pool().Exec(ctx, `
			INSERT INTO log_sources
				(tenant_id, name, host, protocol, port, format, tags, status, eps, parse_rate)
			VALUES ($1,$2,$3,$4,$5,$6,$7,'ok',
				floor(random()*1000+50)::int,
				round((95+random()*5)::numeric,1))
			ON CONFLICT DO NOTHING`,
			tenantID, s.name, s.host, s.proto, s.port, s.format, s.tags)
		if err == nil { srcCount++ }
	}
	fmt.Printf("✓  %d log sources seeded\n", srcCount)

	// ── 3. Seed IOCs từ findings thật ────────────────────────
	tag, _ := db.Pool().Exec(ctx, `
		INSERT INTO iocs (type, value, severity, feed, description, matched)
		SELECT DISTINCT
			'cve'     AS type,
			rule_id   AS value,
			severity,
			'NVD'     AS feed,
			message   AS description,
			true      AS matched
		FROM findings
		WHERE rule_id ILIKE 'CVE-%'
		  AND rule_id NOT IN (SELECT value FROM iocs WHERE type='cve')
		LIMIT 200
		ON CONFLICT (value) DO NOTHING`)
	fmt.Printf("✓  %d CVE IOCs seeded from findings\n", tag.RowsAffected())

	// Thêm IOCs mẫu
	type ioc struct{ typ, val, sev, feed, desc string }
	iocs := []ioc{
		{"hash",   "a3f8c1d9e2b47f6d3a9c2e1b0f4d8e5a2c9b7f3e6d1a4c8b2f5e9d3a7c1b6f4", "HIGH",   "OTX",      "Known malicious build artifact"},
		{"domain", "malicious-cdn.io",       "HIGH",   "MISP",     "C2 domain in supply chain attacks"},
		{"domain", "evil-update-server.net", "HIGH",   "MISP",     "Fake update server - malware delivery"},
		{"ip",     "185.220.101.47",          "MEDIUM", "AbuseIPDB","Known Tor exit node"},
		{"ip",     "45.142.212.100",          "HIGH",   "OTX",      "Known C2 server - Cobalt Strike"},
		{"hash",   "b2e9a4f1c8d37e2b5f0c3a9d6b4e8f2a1c7d5b3f6e0a9c2d4b8e1f7a5c3d9b0", "MEDIUM", "OTX",      "Backdoored npm package"},
	}
	iocCount := 0
	for _, i := range iocs {
		_, err := db.Pool().Exec(ctx, `
			INSERT INTO iocs (type, value, severity, feed, description, matched)
			VALUES ($1,$2,$3,$4,$5,false)
			ON CONFLICT (value) DO NOTHING`,
			i.typ, i.val, i.sev, i.feed, i.desc)
		if err == nil { iocCount++ }
	}
	fmt.Printf("✓  %d sample IOCs seeded\n", iocCount)

	// ── 4. Default playbooks ──────────────────────────────────
	type pbStep struct{ Type, Name, Desc, Config string }
	type pb struct {
		name, desc, trigger, sev string
		steps                    []pbStep
	}
	playbooks := []pb{
		{
			name: "Gate FAIL auto-response", trigger: "gate_fail", sev: "any",
			desc: "Full response: block CI, create Jira ticket, notify team",
			steps: []pbStep{
				{"condition", "Check gate + severity", "FAIL with CRITICAL/HIGH", "gate=FAIL AND severity IN [CRITICAL,HIGH]"},
				{"enrich",    "Enrich findings",       "Add CVE context, EPSS",   "source: NVD,OSV\nfields: [cvss,epss,kev]"},
				{"block",     "Block CI pipeline",     "Fail pipeline check",     "provider: github\nstatus: failure\ncontext: vsp/gate"},
				{"ticket",    "Create Jira ticket",    "Open P1 ticket",          "project: VSP-SECURITY\npriority: P1\nauto_assign: security-team"},
				{"notify",    "Slack alert",           "Alert #security-alerts",  "channel: #security-alerts\nping: @security-oncall"},
				{"notify",    "Email leadership",      "Send exec summary",       "to: ciso@agency.gov\ntemplate: executive_summary"},
				{"remediate", "Auto-assign findings",  "Assign to on-call",       "assignee: security-oncall\npriority: P1\nstatus: in_progress"},
			},
		},
		{
			name: "Critical finding notify", trigger: "critical_finding", sev: "CRITICAL",
			desc: "Immediate Slack + email on critical finding",
			steps: []pbStep{
				{"condition", "Check severity", "CRITICAL only",              "severity=CRITICAL"},
				{"notify",    "Slack alert",    "Post to #security-alerts",   "channel: #security-alerts\nmsg: \"{{severity}} in {{run_id}}\""},
				{"notify",    "Email SOC",      "Send to soc@agency.gov",     "to: soc@agency.gov\nsubject: \"[VSP ALERT] {{severity}}\""},
			},
		},
		{
			name: "Secret detection lockdown", trigger: "secret_detected", sev: "CRITICAL",
			desc: "Credentials found: block CI, create P0 ticket, page on-call",
			steps: []pbStep{
				{"block",   "Block all pipelines", "Immediately fail CI",         "scope: repo\nstatus: failure"},
				{"ticket",  "Create P0 ticket",    "Urgent credential rotation",  "project: VSP-SECURITY\npriority: P0\nlabels: [credential-leak]"},
				{"notify",  "Page on-call",        "PagerDuty alert",             "service: pagerduty\nseverity: critical"},
				{"webhook", "Trigger rotation",    "Call secrets management API", "url: https://vault.internal/v1/rotate\nmethod: POST"},
			},
		},
		{
			name: "SLA breach escalation", trigger: "sla_breach", sev: "any",
			desc: "Escalate to leadership when SLA breached > 24h",
			steps: []pbStep{
				{"condition", "Check breach duration", "Escalate only if >24h",      "breach_age > 24h"},
				{"ticket",    "Create escalation",     "P0 ticket in VSP-ESCALATION","project: VSP-ESCALATION\npriority: P0"},
				{"notify",    "Email CISO",            "Escalation notice",           "to: [ciso@agency.gov,director@agency.gov]"},
			},
		},
	}

	pbCount := 0
	for _, p := range playbooks {
		stepsJSON, _ := json.Marshal(p.steps)
		_, err := db.Pool().Exec(ctx, `
			INSERT INTO playbooks
				(tenant_id, name, description, trigger_event, sev_filter, steps, enabled)
			VALUES ($1,$2,$3,$4,$5,$6,true)
			ON CONFLICT DO NOTHING`,
			tenantID, p.name, p.desc, p.trigger, p.sev, stepsJSON)
		if err == nil { pbCount++ }
	}
	fmt.Printf("✓  %d playbooks seeded\n", pbCount)

	// ── 5. Sample incidents ───────────────────────────────────
	incidents := []struct{ title, sev string }{
		{"API key exposed + gate FAIL — RID_SCHED_20260329", "CRITICAL"},
		{"CVE-2024-45337 detected during deploy window",     "CRITICAL"},
		{"Security score dropped 28pts in 1 hour",           "HIGH"},
		{"SLA breach: 3 unassigned HIGH findings > 14d",     "MEDIUM"},
	}
	incCount := 0
	for _, i := range incidents {
		_, err := db.Pool().Exec(ctx, `
			INSERT INTO incidents (tenant_id, title, severity, status, source_refs)
			VALUES ($1,$2,$3,'open','{}')`,
			tenantID, i.title, i.sev)
		if err == nil { incCount++ }
	}
	fmt.Printf("✓  %d incidents seeded\n", incCount)

	fmt.Println("\n✓  SIEM seed complete — reload browser to see live data")
}
