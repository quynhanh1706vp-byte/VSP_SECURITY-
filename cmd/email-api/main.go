// cmd/email-api/main.go
//
// VSP Email/SMTP microservice (port 8095)
// ─────────────────────────────────────────────────────────────────────
// Stdlib net/smtp client. Default config targets Mailhog (:1025).
// Switch to real SMTP via /config endpoint or env vars.
//
// Storage:
//
//	/var/lib/vsp/email-config.json    SMTP creds + templates
//	/var/lib/vsp/email-history.json   send history (rolling 1000)
//
// Endpoints:
//
//	GET  /healthz
//	GET  /config                  (password masked)
//	POST /config                  update SMTP
//	GET  /config/health           TCP-test SMTP server
//	POST /test                    {"to":"…"} send fixed test email
//	POST /send                    {"to":"…","subject":"…","body":"…","template":"name","vars":{...}}
//	GET  /templates               list pre-seeded + custom
//	POST /templates/{name}        upsert template
//	DELETE /templates/{name}      remove
//	GET  /history?limit=N         rolling send log
//
// Build: go build -o vsp-email-api ./cmd/email-api
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── flags ──────────────────────────────────────────────────────────────

var (
	addr        = flag.String("addr", ":8095", "listen address")
	configPath  = flag.String("config", "/var/lib/vsp/email-config.json", "SMTP config + templates")
	historyPath = flag.String("history", "/var/lib/vsp/email-history.json", "send history")
	maxHistory  = flag.Int("max-history", 1000, "keep last N sends")
)

// ── types ──────────────────────────────────────────────────────────────

type SMTPConfig struct {
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Username    string    `json:"username,omitempty"`
	Password    string    `json:"password,omitempty"` // server-side only
	From        string    `json:"from"`
	FromName    string    `json:"from_name,omitempty"`
	UseTLS      bool      `json:"use_tls"`
	UseSTARTTLS bool      `json:"use_starttls"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

type Template struct {
	Name      string    `json:"name"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	IsHTML    bool      `json:"is_html"`
	UpdatedAt time.Time `json:"updated_at"`
}

type SendRecord struct {
	ID         string    `json:"id"`
	To         []string  `json:"to"`
	Subject    string    `json:"subject"`
	Template   string    `json:"template,omitempty"`
	Status     string    `json:"status"` // sent | failed
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`
}

type errEnv struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// ── globals ────────────────────────────────────────────────────────────

var (
	cfgMu sync.RWMutex
	cfg   SMTPConfig

	tmplMu    sync.RWMutex
	templates = map[string]*Template{}

	histMu  sync.RWMutex
	history []SendRecord
)

// ── helpers ────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, b any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(b)
}
func writeErr(w http.ResponseWriter, code int, msg, detail string) {
	writeJSON(w, code, errEnv{Error: msg, Detail: detail})
}
func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}
func newID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// ── persistence ────────────────────────────────────────────────────────

type configFile struct {
	SMTP      SMTPConfig           `json:"smtp"`
	Templates map[string]*Template `json:"templates"`
}

func loadConfig() {
	b, err := os.ReadFile(*configPath)
	if err != nil {
		// First boot: defaults
		cfgMu.Lock()
		cfg = SMTPConfig{
			Host:     envOr("VSP_SMTP_HOST", "127.0.0.1"),
			Port:     envInt("VSP_SMTP_PORT", 1025),
			From:     envOr("VSP_SMTP_FROM", "vsp@vsp.local"),
			FromName: envOr("VSP_SMTP_FROM_NAME", "VSP DevSecOps"),
			UseTLS:   false, UseSTARTTLS: false,
		}
		cfgMu.Unlock()
		seedTemplates()
		log.Printf("[boot] no config file — using defaults (Mailhog @ %s:%d)", cfg.Host, cfg.Port)
		go persistConfig()
		return
	}
	var c configFile
	if err := json.Unmarshal(b, &c); err != nil {
		log.Printf("[boot] corrupt config: %v — using defaults", err)
		return
	}
	cfgMu.Lock()
	cfg = c.SMTP
	cfgMu.Unlock()
	tmplMu.Lock()
	if c.Templates != nil {
		templates = c.Templates
	}
	tmplMu.Unlock()
	if len(templates) == 0 {
		seedTemplates()
	}
	log.Printf("[boot] loaded SMTP %s:%d, %d templates", cfg.Host, cfg.Port, len(templates))
}

func persistConfig() {
	cfgMu.RLock()
	tmplMu.RLock()
	out := configFile{SMTP: cfg, Templates: templates}
	cfgMu.RUnlock()
	tmplMu.RUnlock()
	b, _ := json.MarshalIndent(out, "", "  ")
	tmp := *configPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("[config] write: %v", err)
		return
	}
	_ = os.Rename(tmp, *configPath)
}

func loadHistory() {
	b, err := os.ReadFile(*historyPath)
	if err != nil {
		return
	}
	var s struct {
		History []SendRecord `json:"history"`
	}
	if json.Unmarshal(b, &s) == nil {
		histMu.Lock()
		history = s.History
		histMu.Unlock()
	}
}

func persistHistory() {
	histMu.RLock()
	out := struct {
		History []SendRecord `json:"history"`
	}{History: history}
	histMu.RUnlock()
	b, _ := json.MarshalIndent(out, "", "  ")
	tmp := *historyPath + ".tmp"
	_ = os.WriteFile(tmp, b, 0o600)
	_ = os.Rename(tmp, *historyPath)
}

func appendHistory(r SendRecord) {
	histMu.Lock()
	history = append(history, r)
	if len(history) > *maxHistory {
		history = history[len(history)-*maxHistory:]
	}
	histMu.Unlock()
	go persistHistory()
}

// ── seed templates ─────────────────────────────────────────────────────

func seedTemplates() {
	now := time.Now().UTC()
	defaults := []*Template{
		{
			Name:    "cve_alert",
			Subject: "[VSP] {{severity}} CVE detected: {{cve}}",
			Body: `A {{severity}} CVE was detected on {{hostname}}.

CVE: {{cve}}
Title: {{title}}
Affected package: {{package}}@{{version}}
Fixed in: {{fixed_in}}
CVSS: {{cvss}}

Open VSP dashboard for full details:
http://{{vsp_host}}:8080/

— VSP DevSecOps Platform`,
			IsHTML: false, UpdatedAt: now,
		},
		{
			Name:    "scan_complete",
			Subject: "[VSP] Trivy scan complete: {{image}}",
			Body: `Trivy scan finished for {{image}}

Findings:
  CRITICAL: {{critical}}
  HIGH:     {{high}}
  MEDIUM:   {{medium}}
  LOW:      {{low}}

Scan duration: {{duration}}
Triggered by:  {{trigger}}

— VSP DevSecOps Platform`,
			IsHTML: false, UpdatedAt: now,
		},
		{
			Name:    "conmon_summary",
			Subject: "[VSP] Weekly compliance summary",
			Body: `VSP Continuous Monitoring summary — {{period}}

Compliance score: {{score}}/100
Frameworks covered: {{frameworks}}

POA&M items: {{poam_open}} open, {{poam_closed}} closed this week
New findings: {{new_findings}}

Read the full ConMon report at:
http://{{vsp_host}}:8080/p4/conmon

— VSP DevSecOps Platform`,
			IsHTML: false, UpdatedAt: now,
		},
		{
			Name:    "signature_failed",
			Subject: "[VSP] Cosign verification FAILED: {{image}}",
			Body: `Cosign signature verification failed.

Image: {{image}}
Reason: {{reason}}
Verified by: {{verifier}}
Time: {{time}}

This may indicate the image was tampered with or signed with the wrong key.

— VSP DevSecOps Platform`,
			IsHTML: false, UpdatedAt: now,
		},
		{
			Name:    "test",
			Subject: "[VSP] SMTP test email",
			Body: `This is a test email from your VSP DevSecOps Platform.

If you're seeing this, your SMTP configuration is working correctly.

Sent at: {{time}}
From service: vsp-email-api on {{hostname}}

— VSP DevSecOps Platform`,
			IsHTML: false, UpdatedAt: now,
		},
	}
	tmplMu.Lock()
	added := 0
	for _, t := range defaults {
		if _, ok := templates[t.Name]; !ok {
			templates[t.Name] = t
			added++
		}
	}
	tmplMu.Unlock()
	if added > 0 {
		log.Printf("[seed] added %d default templates", added)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func envInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

// ── template rendering (simple {{var}} replacement) ────────────────────

func render(s string, vars map[string]any) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", fmt.Sprint(v))
	}
	return s
}

// ── SMTP send ──────────────────────────────────────────────────────────

func sendEmail(to []string, subject, body string, isHTML bool) error {
	cfgMu.RLock()
	c := cfg
	cfgMu.RUnlock()
	if c.Host == "" {
		return fmt.Errorf("SMTP not configured")
	}
	if c.From == "" {
		c.From = "vsp@vsp.local"
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))

	// Build MIME message
	var msg strings.Builder
	if c.FromName != "" {
		fmt.Fprintf(&msg, "From: %s <%s>\r\n", c.FromName, c.From)
	} else {
		fmt.Fprintf(&msg, "From: %s\r\n", c.From)
	}
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	fmt.Fprintf(&msg, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&msg, "MIME-Version: 1.0\r\n")
	if isHTML {
		fmt.Fprintf(&msg, "Content-Type: text/html; charset=UTF-8\r\n")
	} else {
		fmt.Fprintf(&msg, "Content-Type: text/plain; charset=UTF-8\r\n")
	}
	fmt.Fprintf(&msg, "X-Mailer: vsp-email-api/1.0\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	var auth smtp.Auth
	if c.Username != "" {
		auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
	}

	if c.UseTLS {
		// Implicit TLS. MinVersion = TLS 1.2 to refuse legacy SSLv3/TLS1.0/1.1
		// downgrades against the upstream SMTP server.
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName: c.Host,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			return fmt.Errorf("tls dial: %w", err)
		}
		defer conn.Close()
		client, err := smtp.NewClient(conn, c.Host)
		if err != nil {
			return fmt.Errorf("smtp client: %w", err)
		}
		defer client.Quit()
		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("auth: %w", err)
			}
		}
		if err := client.Mail(c.From); err != nil {
			return fmt.Errorf("MAIL: %w", err)
		}
		for _, addr := range to {
			if err := client.Rcpt(addr); err != nil {
				return fmt.Errorf("RCPT %s: %w", addr, err)
			}
		}
		wc, err := client.Data()
		if err != nil {
			return fmt.Errorf("DATA: %w", err)
		}
		if _, err := wc.Write([]byte(msg.String())); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		return wc.Close()
	}

	// Plain or STARTTLS
	return smtp.SendMail(addr, auth, c.From, to, []byte(msg.String()))
}

// ── handlers ───────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	c := cfg
	cfgMu.RUnlock()
	tmplMu.RLock()
	tn := len(templates)
	tmplMu.RUnlock()
	histMu.RLock()
	hn := len(history)
	histMu.RUnlock()
	writeJSON(w, 200, map[string]any{
		"status":      "ok",
		"smtp_host":   c.Host,
		"smtp_port":   c.Port,
		"smtp_from":   c.From,
		"templates":   tn,
		"history":     hn,
		"server_time": time.Now().UTC(),
	})
}

func handleConfigGet(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	c := cfg
	cfgMu.RUnlock()
	// Mask password
	masked := c
	if c.Password != "" {
		masked.Password = "********"
	}
	writeJSON(w, 200, masked)
}

func handleConfigUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeErr(w, 405, "method not allowed", "")
		return
	}
	defer r.Body.Close()
	var c SMTPConfig
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeErr(w, 400, "bad json", err.Error())
		return
	}
	if c.Host == "" {
		writeErr(w, 400, "host required", "")
		return
	}
	if c.Port == 0 {
		c.Port = 25
	}
	cfgMu.Lock()
	// Preserve password if "********" sent (UI doesn't re-send)
	if c.Password == "********" || c.Password == "" {
		c.Password = cfg.Password
	}
	c.UpdatedAt = time.Now().UTC()
	cfg = c
	cfgMu.Unlock()
	go persistConfig()
	writeJSON(w, 200, map[string]any{"status": "saved", "host": c.Host, "port": c.Port})
}

func handleConfigHealth(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	c := cfg
	cfgMu.RUnlock()
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		writeJSON(w, 200, map[string]any{
			"reachable": false,
			"addr":      addr,
			"error":     err.Error(),
		})
		return
	}
	conn.Close()
	writeJSON(w, 200, map[string]any{
		"reachable": true,
		"addr":      addr,
		"latency":   "< 5s",
	})
}

type sendReq struct {
	To       []string       `json:"to"`
	Subject  string         `json:"subject,omitempty"`
	Body     string         `json:"body,omitempty"`
	Template string         `json:"template,omitempty"`
	Vars     map[string]any `json:"vars,omitempty"`
	IsHTML   bool           `json:"is_html,omitempty"`
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", "")
		return
	}
	defer r.Body.Close()
	var req sendReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json", err.Error())
		return
	}
	if len(req.To) == 0 {
		writeErr(w, 400, "to required", "")
		return
	}
	subject := req.Subject
	body := req.Body
	isHTML := req.IsHTML
	if req.Template != "" {
		tmplMu.RLock()
		t, ok := templates[req.Template]
		tmplMu.RUnlock()
		if !ok {
			writeErr(w, 404, "template not found", req.Template)
			return
		}
		// Add useful default vars
		if req.Vars == nil {
			req.Vars = map[string]any{}
		}
		if _, ok := req.Vars["time"]; !ok {
			req.Vars["time"] = time.Now().UTC().Format(time.RFC3339)
		}
		if _, ok := req.Vars["hostname"]; !ok {
			h, _ := os.Hostname()
			req.Vars["hostname"] = h
		}
		if _, ok := req.Vars["vsp_host"]; !ok {
			req.Vars["vsp_host"] = envOr("VSP_HOST", "127.0.0.1")
		}
		subject = render(t.Subject, req.Vars)
		body = render(t.Body, req.Vars)
		isHTML = t.IsHTML
	}
	if subject == "" || body == "" {
		writeErr(w, 400, "subject and body required (or template)", "")
		return
	}

	rec := SendRecord{
		ID:        newID("send"),
		To:        req.To,
		Subject:   subject,
		Template:  req.Template,
		StartedAt: time.Now().UTC(),
	}
	err := sendEmail(req.To, subject, body, isHTML)
	rec.DurationMs = time.Since(rec.StartedAt).Milliseconds()
	if err != nil {
		rec.Status = "failed"
		rec.Error = err.Error()
	} else {
		rec.Status = "sent"
	}
	appendHistory(rec)
	if err != nil {
		writeJSON(w, 500, rec)
		return
	}
	writeJSON(w, 200, rec)
}

func handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", "")
		return
	}
	defer r.Body.Close()
	var req struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json", err.Error())
		return
	}
	if req.To == "" {
		writeErr(w, 400, "to required", "")
		return
	}

	// Send test template
	tmplMu.RLock()
	t, ok := templates["test"]
	tmplMu.RUnlock()
	if !ok {
		seedTemplates()
		tmplMu.RLock()
		t = templates["test"]
		tmplMu.RUnlock()
	}
	hn, _ := os.Hostname()
	vars := map[string]any{
		"time":     time.Now().UTC().Format(time.RFC3339),
		"hostname": hn,
	}
	subject := render(t.Subject, vars)
	body := render(t.Body, vars)

	rec := SendRecord{
		ID:        newID("test"),
		To:        []string{req.To},
		Subject:   subject,
		Template:  "test",
		StartedAt: time.Now().UTC(),
	}
	err := sendEmail([]string{req.To}, subject, body, false)
	rec.DurationMs = time.Since(rec.StartedAt).Milliseconds()
	if err != nil {
		rec.Status = "failed"
		rec.Error = err.Error()
		appendHistory(rec)
		writeJSON(w, 500, rec)
		return
	}
	rec.Status = "sent"
	appendHistory(rec)
	writeJSON(w, 200, rec)
}

func handleTemplatesList(w http.ResponseWriter, r *http.Request) {
	tmplMu.RLock()
	out := make([]*Template, 0, len(templates))
	for _, t := range templates {
		out = append(out, t)
	}
	tmplMu.RUnlock()
	writeJSON(w, 200, map[string]any{"total": len(out), "templates": out})
}

func handleTemplate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/templates/")
	if name == "" {
		handleTemplatesList(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		tmplMu.RLock()
		t, ok := templates[name]
		tmplMu.RUnlock()
		if !ok {
			writeErr(w, 404, "not found", name)
			return
		}
		writeJSON(w, 200, t)
	case http.MethodPost, http.MethodPut:
		var t Template
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			writeErr(w, 400, "bad json", err.Error())
			return
		}
		t.Name = name
		t.UpdatedAt = time.Now().UTC()
		tmplMu.Lock()
		templates[name] = &t
		tmplMu.Unlock()
		go persistConfig()
		writeJSON(w, 200, t)
	case http.MethodDelete:
		tmplMu.Lock()
		_, ok := templates[name]
		delete(templates, name)
		tmplMu.Unlock()
		if !ok {
			writeErr(w, 404, "not found", name)
			return
		}
		go persistConfig()
		writeJSON(w, 200, map[string]any{"status": "deleted", "name": name})
	default:
		writeErr(w, 405, "method not allowed", r.Method)
	}
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	histMu.RLock()
	out := make([]SendRecord, 0, limit)
	for i := len(history) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, history[i])
	}
	histMu.RUnlock()
	writeJSON(w, 200, map[string]any{"total": len(out), "history": out})
}

// ── boot ───────────────────────────────────────────────────────────────

func main() {
	flag.Parse()
	_ = os.MkdirAll(filepath.Dir(*configPath), 0o700)
	loadConfig()
	loadHistory()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", cors(handleHealth))
	mux.HandleFunc("/config", cors(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handleConfigGet(w, r)
			return
		}
		handleConfigUpdate(w, r)
	}))
	mux.HandleFunc("/config/health", cors(handleConfigHealth))
	mux.HandleFunc("/test", cors(handleTest))
	mux.HandleFunc("/send", cors(handleSend))
	mux.HandleFunc("/templates", cors(handleTemplatesList))
	mux.HandleFunc("/templates/", cors(handleTemplate))
	mux.HandleFunc("/history", cors(handleHistory))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("[vsp-email-api] listening on %s — SMTP %s:%d", *addr, cfg.Host, cfg.Port)
	log.Fatal(srv.ListenAndServe())
}
