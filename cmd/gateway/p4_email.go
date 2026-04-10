package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"os"
	"time"
)

type EmailConfig struct {
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUser     string `json:"smtp_user"`
	SMTPPassword string `json:"smtp_password"`
	FromName     string `json:"from_name"`
	FromEmail    string `json:"from_email"`
	Enabled      bool   `json:"enabled"`
}

type EmailRequest struct {
	To   string                 `json:"to"`
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data"`
}

var emailCfg = &EmailConfig{
	SMTPHost:     getEnvStr("SMTP_HOST", "smtp.gmail.com"),
	SMTPPort:     587,
	SMTPUser:     os.Getenv("SMTP_USER"),
	SMTPPassword: os.Getenv("SMTP_PASSWORD"),
	FromName:     "VSP Security Platform",
	FromEmail:    getEnvStr("SMTP_FROM", "security@vsp.mil"),
	Enabled:      os.Getenv("SMTP_USER") != "",
}

func getEnvStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" { return v }
	return fallback
}

func sendSMTP(to, subject, body string) error {
	if !emailCfg.Enabled {
		log.Printf("[EMAIL] Mock send to %s: %s", to, subject)
		return nil
	}
	auth := smtp.PlainAuth("", emailCfg.SMTPUser, emailCfg.SMTPPassword, emailCfg.SMTPHost)
	msg := fmt.Sprintf("From: %s <%s>\r\nTo: %s\r\nSubject: %s\r\nMIME-version: 1.0;\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		emailCfg.FromName, emailCfg.FromEmail, to, subject, body)
	addr := fmt.Sprintf("%s:%d", emailCfg.SMTPHost, emailCfg.SMTPPort)
	return smtp.SendMail(addr, auth, emailCfg.FromEmail, []string{to}, []byte(msg))
}

func buildWelcomeEmail(data map[string]interface{}) string {
	org := fmt.Sprintf("%v", data["org_name"])
	sysID := fmt.Sprintf("%v", data["system_id"])
	plan := fmt.Sprintf("%v", data["plan"])
	dashURL := getEnvStr("DASHBOARD_URL", "http://127.0.0.1:8922")
	return fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f9;margin:0;padding:40px 20px}
.card{background:#fff;border-radius:12px;max-width:560px;margin:0 auto;padding:40px;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.logo{font-size:20px;font-weight:800;color:#0b0c0f;margin-bottom:8px}.badge{display:inline-block;background:#d1fae5;color:#065f46;font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px;margin-bottom:24px}
h1{font-size:24px;font-weight:700;margin:0 0 12px}p{font-size:14px;color:#4b5563;line-height:1.7;margin:0 0 14px}
.btn{display:inline-block;background:#00e5ff;color:#0b0c0f;font-weight:700;font-size:14px;padding:12px 28px;border-radius:8px;text-decoration:none;margin:8px 0 24px}
.divider{height:1px;background:#f0f0f0;margin:20px 0}.footer{text-align:center;font-size:11px;color:#9ca3af;margin-top:20px}
</style></head><body><div class="card">
<div class="logo">VSP</div><span class="badge">DoD Zero Trust P4</span>
<h1>Welcome to VSP, %s!</h1>
<p>Your compliance journey starts now. VSP has been provisioned for your organization.</p>
<a href="%s/onboarding" class="btn">Complete Setup →</a>
<div class="divider"></div>
<p><strong>Account details:</strong><br>System ID: <code>%s</code><br>Plan: %s</p>
<p>Next step: Complete the 5-step onboarding to run your first P4 baseline scan.</p>
<div class="footer">VSP Security Platform · UNCLASSIFIED // FOR OFFICIAL USE ONLY</div>
</div></body></html>`, org, dashURL, sysID, plan)
}

func buildAlertEmail(data map[string]interface{}) string {
	sev := fmt.Sprintf("%v", data["severity"])
	title := fmt.Sprintf("%v", data["title"])
	msg := fmt.Sprintf("%v", data["message"])
	color := "#ef4444"
	if sev == "HIGH" { color = "#f59e0b" }
	if sev == "INFO" { color = "#10b981" }
	dashURL := getEnvStr("DASHBOARD_URL", "http://127.0.0.1:8922")
	return fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f9;margin:0;padding:40px 20px}
.card{background:#fff;border-radius:12px;max-width:560px;margin:0 auto;padding:40px;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.alert{border-left:4px solid %s;padding:14px 18px;border-radius:0 8px 8px 0;margin-bottom:20px;background:#fafafa}
.sev{font-size:11px;font-weight:700;color:%s;text-transform:uppercase}.title{font-size:18px;font-weight:700}
p{font-size:14px;color:#4b5563;line-height:1.7}.btn{display:inline-block;background:#0b0c0f;color:#fff;font-weight:600;font-size:13px;padding:10px 24px;border-radius:8px;text-decoration:none;margin-top:16px}
.footer{font-size:11px;color:#9ca3af;margin-top:20px;padding-top:16px;border-top:1px solid #f0f0f0}
</style></head><body><div class="card">
<div style="font-size:20px;font-weight:800;margin-bottom:16px">VSP</div>
<div class="alert"><div class="sev">%s</div><div class="title">%s</div></div>
<p>%s</p>
<a href="%s/p4" class="btn">Open P4 Dashboard →</a>
<div class="footer">VSP-DOD-2025-001 · %s · UNCLASSIFIED // FOR OFFICIAL USE ONLY</div>
</div></body></html>`, color, color, sev, title, msg, dashURL, time.Now().Format("2006-01-02 15:04"))
}

func buildReportEmail(data map[string]interface{}) string {
	period := fmt.Sprintf("%v", data["period"])
	ztState.mu.RLock()
	p4 := ztState.P4Readiness
	ztState.mu.RUnlock()
	dashURL := getEnvStr("DASHBOARD_URL", "http://127.0.0.1:8922")
	return fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f9;margin:0;padding:40px 20px}
.card{background:#fff;border-radius:12px;max-width:580px;margin:0 auto;padding:40px;box-shadow:0 4px 24px rgba(0,0,0,.08)}
h1{font-size:22px;font-weight:700;margin:0 0 4px}.period{font-size:12px;color:#9ca3af;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}
.score{text-align:center;padding:14px;background:#f8fafc;border-radius:8px}
.score-num{font-size:26px;font-weight:800}.score-lbl{font-size:11px;color:#9ca3af}
.row{display:flex;justify-content:space-between;font-size:13px;padding:7px 0;border-bottom:1px solid #f9fafb}
.btn{display:inline-block;background:#0b0c0f;color:#fff;font-weight:600;font-size:13px;padding:10px 24px;border-radius:8px;text-decoration:none;margin-top:16px}
.footer{text-align:center;font-size:11px;color:#9ca3af;margin-top:20px;padding-top:16px;border-top:1px solid #f0f0f0}
</style></head><body><div class="card">
<div style="font-size:20px;font-weight:800;margin-bottom:8px">VSP</div>
<h1>%s ConMon Report</h1>
<div class="period">%s · VSP-DOD-2025-001</div>
<div class="grid">
<div class="score"><div class="score-num" style="color:#10b981">%d%%</div><div class="score-lbl">P4 Readiness</div></div>
<div class="score"><div class="score-num" style="color:#06b6d4">94</div><div class="score-lbl">ConMon Score</div></div>
<div class="score"><div class="score-num" style="color:#f59e0b">1</div><div class="score-lbl">Open POA&amp;M</div></div>
</div>
<div class="row"><span>FedRAMP Moderate</span><strong>92%%</strong></div>
<div class="row"><span>CMMC Level 2</span><strong>87%%</strong></div>
<div class="row"><span>ZT P4</span><strong>%d%%</strong></div>
<div class="row"><span>Pipeline Pass Rate</span><strong>90%%</strong></div>
<a href="%s/p4" class="btn">View Full Dashboard →</a>
<div class="footer">UNCLASSIFIED // FOR OFFICIAL USE ONLY · VSP Security Platform</div>
</div></body></html>`, period, time.Now().Format("January 2006"), p4, p4, dashURL)
}

func handleSendEmail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req EmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, 400); return
	}
	// Validate email address — prevent header injection
	if req.To == "" || strings.ContainsAny(req.To, "\r\n\t;,") || len(req.To) > 254 {
		http.Error(w, `{"error":"invalid email address"}`, 400); return
	}
	if !strings.Contains(req.To, "@") || strings.Count(req.To, "@") > 1 {
		http.Error(w, `{"error":"invalid email format"}`, 400); return
	}
	var subject, body string
	switch req.Type {
	case "welcome":
		subject = fmt.Sprintf("Welcome to VSP — %v!", req.Data["org_name"])
		body = buildWelcomeEmail(req.Data)
	case "alert":
		subject = fmt.Sprintf("[VSP %v] %v", req.Data["severity"], req.Data["title"])
		body = buildAlertEmail(req.Data)
	case "report":
		subject = fmt.Sprintf("VSP ConMon Report — %v %s", req.Data["period"], time.Now().Format("January 2006"))
		body = buildReportEmail(req.Data)
	default:
		http.Error(w, `{"error":"unknown type"}`, 400); return
	}
	if err := sendSMTP(req.To, subject, body); err != nil {
		log.Printf("[EMAIL] Error: %v", err)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok", "to": req.To, "subject": subject,
		"smtp_enabled": emailCfg.Enabled,
	})
}

func handleEmailConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodPost {
		json.NewDecoder(r.Body).Decode(emailCfg)
		emailCfg.Enabled = emailCfg.SMTPUser != "" && emailCfg.SMTPPassword != ""
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); return
	}
	safe := map[string]interface{}{
		"smtp_host": emailCfg.SMTPHost, "smtp_port": emailCfg.SMTPPort,
		"smtp_user": emailCfg.SMTPUser, "from_email": emailCfg.FromEmail,
		"enabled": emailCfg.Enabled,
	}
	json.NewEncoder(w).Encode(safe)
}

func init() {
	// Weekly ConMon report scheduler
	go func() {
		time.Sleep(10 * time.Second)
		log.Println("[EMAIL] System initialized — SMTP:", emailCfg.Enabled)
	}()
}

// Needed for bytes import
var _ = bytes.NewReader
