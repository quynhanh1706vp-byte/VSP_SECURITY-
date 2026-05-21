// cmd/sw-inventory/main.go
//
// VSP Software Inventory microservice (port 8094)
// ────────────────────────────────────────────────────────────────────────
// Replaces the broken /api/v1/software-inventory/report path on the gateway
// (CSRF token middleware blocked agent POSTs → silent data loss).
//
// This service is X-Agent-Key authenticated for agent ingestion, NOT
// CSRF-protected. UI endpoints are open by default but can be locked
// with /etc/vsp/ui.key (Bearer auth).
//
// Storage: atomic JSON file at /var/lib/vsp/sw-inventory.json
//
//	(same pattern as cosign-api, no CGO/SQLite needed).
//
// Endpoints
//
//	POST /agent/report                — agent push (X-Agent-Key required)
//	GET  /healthz                     — liveness + counts
//	GET  /hosts                       — list (?os=&search=&min_risk=)
//	GET  /hosts/{name}                — host detail
//	GET  /hosts/{name}/packages       — package list
//	GET  /hosts/{name}/cves           — CVE matches
//	DELETE /hosts/{name}              — remove host
//	GET  /stats                       — KPIs (dashboard)
//	GET  /audit                       — agent submission audit log
//	POST /cve-match                   — re-run CVE correlation
//	GET  /export/csv                  — CSV export of hosts + risk
//
// Build: go build -o vsp-sw-inventory ./cmd/sw-inventory
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ── flags ──────────────────────────────────────────────────────────────

var (
	addr      = flag.String("addr", ":8094", "listen address")
	storePath = flag.String("store", "/var/lib/vsp/sw-inventory.json", "JSON store path")
	auditPath = flag.String("audit", "/var/lib/vsp/sw-audit.json", "audit log path (rolling)")
	keyFile   = flag.String("agent-key-file", "/etc/vsp/sw-agent.key", "agent API key file (autogen if missing)")
	uiKeyFile  = flag.String("ui-key-file", "/etc/vsp/ui.key", "UI API key file (optional; if absent, UI endpoints are open)")
	pgURL     = flag.String("pg", "postgres://vsp:vsp@127.0.0.1:5432/vsp_go", "Postgres DSN for direct sync (empty to disable)")
	maxAudit  = flag.Int("max-audit", 5000, "keep last N audit events")
)

// ── globals ────────────────────────────────────────────────────────────

var (
	store = struct {
		sync.RWMutex
		Hosts map[string]*Host `json:"hosts"`
	}{Hosts: map[string]*Host{}}

	audit = struct {
		sync.RWMutex
		Events []AuditEvent `json:"events"`
	}{Events: []AuditEvent{}}

	agentKey string
	pgPool   *pgxpool.Pool
	uiKey    string // empty = open
)

// ── types ──────────────────────────────────────────────────────────────

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source,omitempty"` // dpkg, rpm, pip, npm, gem
	Arch    string `json:"arch,omitempty"`
}

type CVEMatch struct {
	CVE      string  `json:"cve"`
	Severity string  `json:"severity"`
	Package  string  `json:"package"`
	Version  string  `json:"version"`
	FixedIn  string  `json:"fixed_in,omitempty"`
	CVSS     float64 `json:"cvss,omitempty"`
	Title    string  `json:"title,omitempty"`
}

type Host struct {
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	OSVersion    string     `json:"os_version"`
	Kernel       string     `json:"kernel"`
	IPAddress    string     `json:"ip_address"`
	AgentVersion string     `json:"agent_version"`
	Packages     []Package  `json:"packages"`
	CVEs         []CVEMatch `json:"cves,omitempty"`
	FirstSeen    time.Time  `json:"first_seen"`
	LastSeen     time.Time  `json:"last_seen"`
	ReportCount  int        `json:"report_count"`
}

// computed
func (h *Host) RiskScore() int {
	c, hi, m, l := h.CVECounts()
	return c*10 + hi*5 + m*2 + l*1
}

func (h *Host) CVECounts() (crit, high, med, low int) {
	for _, c := range h.CVEs {
		switch c.Severity {
		case "CRITICAL":
			crit++
		case "HIGH":
			high++
		case "MEDIUM":
			med++
		case "LOW":
			low++
		}
	}
	return
}

type AgentReport struct {
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	OSVersion    string    `json:"os_version"`
	Kernel       string    `json:"kernel"`
	IPAddress    string    `json:"ip_address"`
	AgentVersion string    `json:"agent_version"`
	Packages     []Package `json:"packages"`
	CollectedAt  time.Time `json:"collected_at,omitempty"`
}

type AuditEvent struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname,omitempty"`
	IP       string    `json:"ip,omitempty"`
	Action   string    `json:"action"`
	Status   string    `json:"status"`
	Detail   string    `json:"detail,omitempty"`
}

type errEnvelope struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// ── helpers ────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, code int, msg, detail string) {
	writeJSON(w, code, errEnvelope{Error: msg, Detail: detail})
}

func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Agent-Key, X-API-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func requireAgentKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		k := r.Header.Get("X-Agent-Key")
		if k == "" || k != agentKey {
			writeAudit("", clientIP(r), "report", "unauthorized", "missing or wrong X-Agent-Key")
			writeErr(w, 401, "invalid agent key", "set X-Agent-Key header (see /etc/vsp/sw-agent.key)")
			return
		}
		next(w, r)
	}
}

func requireUIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if uiKey == "" {
			next(w, r)
			return
		}
		k := r.Header.Get("X-API-Key")
		if k == "" {
			if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
				k = strings.TrimPrefix(a, "Bearer ")
			}
		}
		if k != uiKey {
			writeErr(w, 401, "missing or invalid API key", "")
			return
		}
		next(w, r)
	}
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.SplitN(ip, ",", 2)[0]
	}
	return strings.SplitN(r.RemoteAddr, ":", 2)[0]
}

// ── persistence ────────────────────────────────────────────────────────

func loadStore() {
	b, err := os.ReadFile(*storePath)
	if err != nil {
		return // first boot
	}
	var s struct {
		Hosts map[string]*Host `json:"hosts"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		log.Printf("[store] corrupt %s: %v — starting fresh", *storePath, err)
		return
	}
	if s.Hosts == nil {
		return
	}
	store.Lock()
	store.Hosts = s.Hosts
	store.Unlock()
	log.Printf("[store] loaded %d hosts from %s", len(s.Hosts), *storePath)
}

func persistStore() {
	store.RLock()
	b, err := json.MarshalIndent(struct {
		Hosts map[string]*Host `json:"hosts"`
	}{Hosts: store.Hosts}, "", "  ")
	store.RUnlock()
	if err != nil {
		log.Printf("[store] marshal: %v", err)
		return
	}
	tmp := *storePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("[store] write %s: %v", tmp, err)
		return
	}
	_ = os.Rename(tmp, *storePath)
}

func loadAudit() {
	b, err := os.ReadFile(*auditPath)
	if err != nil {
		return
	}
	var a struct {
		Events []AuditEvent `json:"events"`
	}
	if json.Unmarshal(b, &a) == nil && a.Events != nil {
		audit.Lock()
		audit.Events = a.Events
		audit.Unlock()
		log.Printf("[audit] loaded %d events", len(a.Events))
	}
}

func persistAudit() {
	audit.RLock()
	b, _ := json.MarshalIndent(struct {
		Events []AuditEvent `json:"events"`
	}{Events: audit.Events}, "", "  ")
	audit.RUnlock()
	tmp := *auditPath + ".tmp"
	_ = os.WriteFile(tmp, b, 0o600)
	_ = os.Rename(tmp, *auditPath)
}

// ── audit logging ──────────────────────────────────────────────────────

var auditID int64

func writeAudit(host, ip, action, status, detail string) {
	go func() {
		audit.Lock()
		auditID++
		ev := AuditEvent{
			ID: auditID, Time: time.Now().UTC(),
			Hostname: host, IP: ip, Action: action, Status: status, Detail: detail,
		}
		audit.Events = append(audit.Events, ev)
		// trim
		if len(audit.Events) > *maxAudit {
			audit.Events = audit.Events[len(audit.Events)-*maxAudit:]
		}
		audit.Unlock()
		go persistAudit()
	}()
}

// ── key loading (autogen if missing) ───────────────────────────────────

func loadOrGenKey(path string, autogen bool) (string, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	if !os.IsNotExist(err) || !autogen {
		return "", err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	k := hex.EncodeToString(raw)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, []byte(k+"\n"), 0o600); err != nil {
		return "", err
	}
	log.Printf("[boot] auto-generated %s (mode 640) — share with agents", path)
	return k, nil
}

// ── handlers ───────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	store.RLock()
	hosts := len(store.Hosts)
	pkgs, cves := 0, 0
	for _, h := range store.Hosts {
		pkgs += len(h.Packages)
		cves += len(h.CVEs)
	}
	store.RUnlock()
	writeJSON(w, 200, map[string]any{
		"status":      "ok",
		"hosts":       hosts,
		"packages":    pkgs,
		"cve_matches": cves,
		"store":       *storePath,
		"agent_auth":  "X-Agent-Key required",
		"ui_auth":     uiKey != "",
		"server_time": time.Now().UTC(),
	})
}


// forwardToGateway syncs an AgentReport to the gateway ReceiveReport handler
// so that Postgres (software_assets + software_findings) stays in sync with
// the JSON store.  Runs in a goroutine — never blocks the agent response.

// initPgPool connects to Postgres once at boot (optional — won't crash if unavailable).
func initPgPool() {
	if pgURL == nil || *pgURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, *pgURL)
	if err != nil {
		log.Printf("[pg-sync] connect error (sync disabled): %v", err)
		return
	}
	if err := pool.Ping(ctx); err != nil {
		log.Printf("[pg-sync] ping error (sync disabled): %v", err)
		pool.Close()
		return
	}
	pgPool = pool
	log.Printf("[pg-sync] connected to Postgres — direct sync enabled")
}

// syncToPostgres upserts host + package findings into Postgres.
// Mirrors the logic in internal/api/handler/software_inventory.go ReceiveReport.
// Runs in a goroutine — never blocks the agent response.
func syncToPostgres(rep AgentReport) {
	if pgPool == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	crackPatterns := []string{"_crack_", "-crack-", ".crack.", "_keygen", "-keygen", "warez", "nulled", "pirated", "kmspico", "daz-loader", "ratiborus", "re-loader", "kmsauto", "_activator", "activator_", "windows-activat"}
	suspPatterns := []string{"torrent", "utorrent", "xmrig", "minerd", "cpuminer"}

	crackCount, eolCount, suspCount := 0, 0, 0
	now := rep.CollectedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	for _, pkg := range rep.Packages {
		label := strings.ToLower(pkg.Name)
		isCrack, isSusp := false, false
		suspReason := ""
		for _, p := range crackPatterns {
			if strings.Contains(label, p) {
				isCrack = true
				suspReason = "crack/keygen pattern"
				break
			}
		}
		if !isCrack {
			for _, p := range suspPatterns {
				if strings.Contains(label, p) {
					isSusp = true
					suspReason = "suspicious pattern"
					break
				}
			}
		}
		// EOL check
		var eolHits int
		_ = pgPool.QueryRow(ctx,
			`SELECT COUNT(*) FROM eol_database WHERE product_name ILIKE $1 AND status='eol'`,
			"%"+strings.Split(pkg.Name, " ")[0]+"%",
		).Scan(&eolHits)
		isEOL := eolHits > 0

		if isCrack { crackCount++ } else if isEOL { eolCount++ } else if isSusp { suspCount++ }

		_, err := pgPool.Exec(ctx, `
			INSERT INTO software_findings
				(hostname,name,version,publisher,sha256,signed,suspicious,susp_reason,source,detected_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (hostname,name,version) DO UPDATE SET
				suspicious=EXCLUDED.suspicious, susp_reason=EXCLUDED.susp_reason,
				detected_at=EXCLUDED.detected_at`,
			rep.Hostname, pkg.Name, pkg.Version, "", "", false,
			isCrack||isSusp, suspReason, pkg.Source, now)
		if err != nil {
			log.Printf("[pg-sync] findings upsert error: %v", err)
			return
		}
	}

	// Risk score
	raw := crackCount*30 + eolCount*20 + suspCount*10
	if raw > 100 { raw = 100 }
	riskLevel := "clean"
	switch {
	case raw >= 70: riskLevel = "critical"
	case raw >= 40: riskLevel = "high"
	case raw >= 10: riskLevel = "medium"
	}

	reportJSON, _ := json.Marshal(rep)
	_, err := pgPool.Exec(ctx, `
		INSERT INTO software_assets
			(hostname,os,os_version,arch,agent_version,
			 total_software,suspicious_count,eol_count,crack_count,
			 risk_score,risk_level,last_seen,report_json,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
		ON CONFLICT (hostname) DO UPDATE SET
			os=EXCLUDED.os, os_version=EXCLUDED.os_version,
			arch=EXCLUDED.arch, agent_version=EXCLUDED.agent_version,
			total_software=EXCLUDED.total_software,
			suspicious_count=EXCLUDED.suspicious_count,
			eol_count=EXCLUDED.eol_count, crack_count=EXCLUDED.crack_count,
			risk_score=EXCLUDED.risk_score, risk_level=EXCLUDED.risk_level,
			last_seen=EXCLUDED.last_seen, report_json=EXCLUDED.report_json,
			updated_at=NOW()`,
		rep.Hostname, rep.OS, rep.OSVersion, "", rep.AgentVersion,
		len(rep.Packages), suspCount, eolCount, crackCount,
		raw, riskLevel, now, reportJSON)
	if err != nil {
		log.Printf("[pg-sync] assets upsert error: %v", err)
		return
	}
	log.Printf("[pg-sync] synced host=%s pkgs=%d risk=%s(%d) crack=%d eol=%d susp=%d",
		rep.Hostname, len(rep.Packages), riskLevel, raw, crackCount, eolCount, suspCount)
}


func handleAgentReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", "")
		return
	}
	defer r.Body.Close()
	var rep AgentReport
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		writeAudit("", clientIP(r), "report", "rejected", "bad json: "+err.Error())
		writeErr(w, 400, "bad json", err.Error())
		return
	}
	rep.Hostname = strings.TrimSpace(rep.Hostname)
	if rep.Hostname == "" {
		writeAudit("", clientIP(r), "report", "rejected", "missing hostname")
		writeErr(w, 400, "hostname required", "")
		return
	}
	if rep.CollectedAt.IsZero() {
		rep.CollectedAt = time.Now().UTC()
	}

	store.Lock()
	now := time.Now().UTC()
	h, exists := store.Hosts[rep.Hostname]
	if !exists {
		h = &Host{Hostname: rep.Hostname, FirstSeen: now}
		store.Hosts[rep.Hostname] = h
	}
	h.OS = rep.OS
	h.OSVersion = rep.OSVersion
	h.Kernel = rep.Kernel
	h.IPAddress = rep.IPAddress
	if rep.IPAddress == "" {
		h.IPAddress = clientIP(r)
	}
	h.AgentVersion = rep.AgentVersion
	h.Packages = rep.Packages
	h.LastSeen = now
	h.ReportCount++
	// Re-match CVEs for this host immediately
	h.CVEs = matchCVEsForHost(h)
	store.Unlock()

	go persistStore()
	go syncToPostgres(rep)

	writeAudit(rep.Hostname, clientIP(r), "report", "accepted",
		fmt.Sprintf("%d packages, %d cves, agent=%s", len(rep.Packages), len(h.CVEs), rep.AgentVersion))

	writeJSON(w, 200, map[string]any{
		"status":   "accepted",
		"hostname": rep.Hostname,
		"packages": len(rep.Packages),
		"cves":     len(h.CVEs),
		"server":   now,
	})
}

func handleHostsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	osFilter := strings.ToLower(q.Get("os"))
	search := strings.ToLower(q.Get("search"))
	minRisk, _ := strconv.Atoi(q.Get("min_risk"))

	store.RLock()
	out := make([]map[string]any, 0, len(store.Hosts))
	for _, h := range store.Hosts {
		if osFilter != "" && !strings.Contains(strings.ToLower(h.OS), osFilter) {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(h.Hostname), search) {
			continue
		}
		risk := h.RiskScore()
		if risk < minRisk {
			continue
		}
		c, hi, m, l := h.CVECounts()
		out = append(out, map[string]any{
			"hostname":      h.Hostname,
			"os":            h.OS,
			"os_version":    h.OSVersion,
			"kernel":        h.Kernel,
			"ip_address":    h.IPAddress,
			"agent_version": h.AgentVersion,
			"package_count": len(h.Packages),
			"cve_critical":  c,
			"cve_high":      hi,
			"cve_medium":    m,
			"cve_low":       l,
			"risk_score":    risk,
			"last_seen":     h.LastSeen,
			"first_seen":    h.FirstSeen,
			"report_count":  h.ReportCount,
		})
	}
	store.RUnlock()

	// Sort by risk descending
	sort.Slice(out, func(i, j int) bool {
		return out[i]["risk_score"].(int) > out[j]["risk_score"].(int)
	})

	writeJSON(w, 200, map[string]any{"total": len(out), "hosts": out})
}

func handleHostDetail(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/hosts/")
	rest = strings.TrimSuffix(rest, "/")

	if r.Method == http.MethodDelete {
		store.Lock()
		_, ok := store.Hosts[rest]
		delete(store.Hosts, rest)
		store.Unlock()
		if !ok {
			writeErr(w, 404, "host not found", rest)
			return
		}
		go persistStore()
		writeAudit(rest, clientIP(r), "delete", "ok", "")
		writeJSON(w, 200, map[string]any{"status": "deleted", "hostname": rest})
		return
	}

	if i := strings.Index(rest, "/"); i >= 0 {
		host := rest[:i]
		sub := rest[i+1:]
		store.RLock()
		h, ok := store.Hosts[host]
		store.RUnlock()
		if !ok {
			writeErr(w, 404, "host not found", host)
			return
		}
		switch sub {
		case "packages":
			writeJSON(w, 200, map[string]any{"hostname": host, "total": len(h.Packages), "packages": h.Packages})
		case "cves":
			writeJSON(w, 200, map[string]any{"hostname": host, "total": len(h.CVEs), "cves": h.CVEs})
		default:
			writeErr(w, 404, "unknown sub-resource", sub)
		}
		return
	}

	store.RLock()
	h, ok := store.Hosts[rest]
	store.RUnlock()
	if !ok {
		writeErr(w, 404, "host not found", rest)
		return
	}
	c, hi, m, l := h.CVECounts()
	writeJSON(w, 200, map[string]any{
		"hostname":      h.Hostname,
		"os":            h.OS,
		"os_version":    h.OSVersion,
		"kernel":        h.Kernel,
		"ip_address":    h.IPAddress,
		"agent_version": h.AgentVersion,
		"package_count": len(h.Packages),
		"packages":      h.Packages,
		"cves":          h.CVEs,
		"cve_critical":  c,
		"cve_high":      hi,
		"cve_medium":    m,
		"cve_low":       l,
		"risk_score":    h.RiskScore(),
		"first_seen":    h.FirstSeen,
		"last_seen":     h.LastSeen,
		"report_count":  h.ReportCount,
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	store.RLock()
	defer store.RUnlock()

	hosts := len(store.Hosts)
	pkgs, totalCVE := 0, 0
	c, hi, m, l := 0, 0, 0, 0
	stale := 0
	staleThreshold := time.Now().UTC().Add(-24 * time.Hour)
	osCount := map[string]int{}
	topRisk := []map[string]any{}

	for _, h := range store.Hosts {
		pkgs += len(h.Packages)
		totalCVE += len(h.CVEs)
		hc, hh, hm, hl := h.CVECounts()
		c += hc
		hi += hh
		m += hm
		l += hl
		if h.LastSeen.Before(staleThreshold) {
			stale++
		}
		osCount[h.OS]++
		topRisk = append(topRisk, map[string]any{
			"hostname":   h.Hostname,
			"risk_score": h.RiskScore(),
		})
	}
	sort.Slice(topRisk, func(i, j int) bool {
		return topRisk[i]["risk_score"].(int) > topRisk[j]["risk_score"].(int)
	})
	if len(topRisk) > 10 {
		topRisk = topRisk[:10]
	}

	writeJSON(w, 200, map[string]any{
		"hosts":           hosts,
		"hosts_stale_24h": stale,
		"packages":        pkgs,
		"cve_total":       totalCVE,
		"cve_critical":    c,
		"cve_high":        hi,
		"cve_medium":      m,
		"cve_low":         l,
		"by_os":           osCount,
		"top_risk":        topRisk,
		"server_time":     time.Now().UTC(),
	})
}

func handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	hostFilter := r.URL.Query().Get("host")

	audit.RLock()
	out := make([]AuditEvent, 0, limit)
	for i := len(audit.Events) - 1; i >= 0 && len(out) < limit; i-- {
		ev := audit.Events[i]
		if hostFilter != "" && ev.Hostname != hostFilter {
			continue
		}
		out = append(out, ev)
	}
	audit.RUnlock()
	writeJSON(w, 200, map[string]any{"total": len(out), "events": out})
}

func handleCVEMatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", "")
		return
	}
	store.Lock()
	count := 0
	for _, h := range store.Hosts {
		h.CVEs = matchCVEsForHost(h)
		count += len(h.CVEs)
	}
	store.Unlock()
	go persistStore()
	writeAudit("", clientIP(r), "cve-match", "ok",
		fmt.Sprintf("%d total matches across %d hosts", count, len(store.Hosts)))
	writeJSON(w, 200, map[string]any{
		"status":      "ok",
		"hosts":       len(store.Hosts),
		"cve_matches": count,
		"server":      time.Now().UTC(),
	})
}

func handleExportCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"sw-inventory.csv\"")
	w.Write([]byte("hostname,os,os_version,kernel,ip,agent,packages,cve_critical,cve_high,cve_medium,cve_low,risk_score,last_seen\n"))
	store.RLock()
	defer store.RUnlock()
	hosts := make([]*Host, 0, len(store.Hosts))
	for _, h := range store.Hosts {
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].RiskScore() > hosts[j].RiskScore() })
	for _, h := range hosts {
		c, hi, m, l := h.CVECounts()
		fmt.Fprintf(w, "%q,%q,%q,%q,%s,%s,%d,%d,%d,%d,%d,%d,%s\n",
			h.Hostname, h.OS, h.OSVersion, h.Kernel,
			h.IPAddress, h.AgentVersion, len(h.Packages),
			c, hi, m, l, h.RiskScore(), h.LastSeen.Format(time.RFC3339))
	}
}

// ── boot ───────────────────────────────────────────────────────────────

// ── alias handlers cho frontend sw_inventory.html ─────────────────────
// Frontend gọi /inventory, /whitelist, /blacklist, /cracks, /licenses, /scan-history
// Map về các endpoints thật của service

func handleInventory(w http.ResponseWriter, r *http.Request) {
	// /inventory → /hosts với format {items:[]}
	store.RLock()
	out := make([]map[string]any, 0, len(store.Hosts))
	for _, h := range store.Hosts {
		c, hi, m, l := h.CVECounts()
		out = append(out, map[string]any{
			"hostname":      h.Hostname,
			"os":            h.OS,
			"os_version":    h.OSVersion,
			"ip_address":    h.IPAddress,
			"package_count": len(h.Packages),
			"cve_critical":  c,
			"cve_high":      hi,
			"cve_medium":    m,
			"cve_low":       l,
			"risk_score":    h.RiskScore(),
			"last_seen":     h.LastSeen,
		})
	}
	store.RUnlock()
	writeJSON(w, 200, map[string]any{"items": out, "total": len(out)})
}

func handleWhitelist(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": []any{}})
}

func handleBlacklist(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": []any{}})
}

func handleCracks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": []any{}})
}

func handleLicenses(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": []any{}, "total": 0})
}

func handleScanHistory(w http.ResponseWriter, r *http.Request) {
	audit.RLock()
	items := make([]map[string]any, 0, len(audit.Events))
	for _, e := range audit.Events {
		items = append(items, map[string]any{
			"id":       e.ID,
			"time":     e.Time,
			"hostname": e.Hostname,
			"action":   e.Action,
			"status":   e.Status,
		})
	}
	audit.RUnlock()
	writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
}


func main() {
	flag.Parse()
	initPgPool()

	_ = os.MkdirAll(filepath.Dir(*storePath), 0o700)
	loadStore()
	loadAudit()
	// init auditID
	audit.RLock()
	if len(audit.Events) > 0 {
		auditID = audit.Events[len(audit.Events)-1].ID
	}
	audit.RUnlock()

	var err error
	agentKey, err = loadOrGenKey(*keyFile, true)
	if err != nil {
		log.Fatalf("[boot] load agent key: %v", err)
	}
	log.Printf("[boot] agent key from %s (len=%d)", *keyFile, len(agentKey))

	if _, errStat := os.Stat(*uiKeyFile); errStat == nil {
		uiKey, _ = loadOrGenKey(*uiKeyFile, false)
		if uiKey != "" {
			log.Printf("[boot] UI auth ENABLED")
		}
	} else {
		log.Printf("[boot] UI auth DISABLED (no %s)", *uiKeyFile)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", cors(handleHealth))
	mux.HandleFunc("/agent/report", cors(requireAgentKey(handleAgentReport)))
	mux.HandleFunc("/hosts", cors(requireUIKey(handleHostsList)))
	mux.HandleFunc("/hosts/", cors(requireUIKey(handleHostDetail)))
	mux.HandleFunc("/stats", cors(requireUIKey(handleStats)))
	mux.HandleFunc("/audit", cors(requireUIKey(handleAudit)))
	mux.HandleFunc("/cve-match", cors(requireUIKey(handleCVEMatch)))
	mux.HandleFunc("/export/csv", cors(requireUIKey(handleExportCSV)))
	// Alias endpoints cho sw_inventory.html frontend
	mux.HandleFunc("/inventory",    cors(requireUIKey(handleInventory)))
	mux.HandleFunc("/whitelist",    cors(requireUIKey(handleWhitelist)))
	mux.HandleFunc("/blacklist",    cors(requireUIKey(handleBlacklist)))
	mux.HandleFunc("/cracks",       cors(requireUIKey(handleCracks)))
	mux.HandleFunc("/licenses",     cors(requireUIKey(handleLicenses)))
	mux.HandleFunc("/scan-history", cors(requireUIKey(handleScanHistory)))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("[vsp-sw-inventory] listening on %s — store=%s", *addr, *storePath)

	// Re-match CVEs once at boot (rules may have changed)
	go func() {
		time.Sleep(500 * time.Millisecond)
		store.Lock()
		count := 0
		for _, h := range store.Hosts {
			h.CVEs = matchCVEsForHost(h)
			count += len(h.CVEs)
		}
		store.Unlock()
		go persistStore()
		log.Printf("[boot] CVE re-match: %d matches across %d hosts", count, len(store.Hosts))
	}()

	log.Fatal(srv.ListenAndServe())
}
