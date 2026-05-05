// cmd/dast-api/main.go
//
// VSP DAST microservice (port 8093)
// ─────────────────────────────────────────────────────────────────────
// Wraps `nuclei` CLI for dynamic security testing.
//
// Architecture:
//   • Async scans: POST /scan → returns scan_id immediately, scan runs
//     in background goroutine, results visible via GET /scans/{id}.
//   • One scan at a time (scanMutex). Concurrent requests queue (limited).
//   • Parser converts nuclei JSONL output → unified Finding[].
//   • JSON store atomic-rename pattern.
//
// Profiles:
//   quick    nuclei -t cves/ -severity high,critical    (~30s)
//   standard nuclei -t cves/ -severity medium,high,critical  (~3m)
//   deep     nuclei -t cves/,vulnerabilities/,exposures/  (~10m+)
//
// Endpoints:
//   GET    /healthz                liveness + tools detected
//   GET    /tools/check            which DAST tools available
//   POST   /scan                   {"target":"https://x","profile":"quick"}
//   GET    /scans                  list (sort by started_at desc)
//   GET    /scans/{id}             detail (status + findings)
//   GET    /scans/{id}/findings    findings only
//   POST   /scans/{id}/cancel      cancel running scan
//   DELETE /scans/{id}             delete record
//   GET    /stats                  KPIs
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── flags ──────────────────────────────────────────────────────────────

var (
	addr       = flag.String("addr", ":8093", "listen address")
	storePath  = flag.String("store", "/var/lib/vsp/dast-scans.json", "scan store path")
	maxScans   = flag.Int("max-scans", 200, "rolling window")
	nucleiBin  = flag.String("nuclei", "nuclei", "nuclei binary path or 'nuclei' to use $PATH")
	maxParallel = flag.Int("parallel", 1, "max concurrent scans")
)

// ── types ──────────────────────────────────────────────────────────────

type Scan struct {
	ID         string     `json:"id"`
	Target     string     `json:"target"`
	Profile    string     `json:"profile"`
	Status     string     `json:"status"` // queued | running | done | failed | cancelled
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt time.Time  `json:"finished_at,omitempty"`
	DurationMs int64      `json:"duration_ms"`
	Tool       string     `json:"tool"` // nuclei
	Findings   []Finding  `json:"findings,omitempty"`
	Stats      ScanStats  `json:"stats"`
	Error      string     `json:"error,omitempty"`
	RawOutput  string     `json:"raw_output,omitempty"` // truncated stderr/stdout for debug

	// runtime
	cancel context.CancelFunc `json:"-"`
}

type Finding struct {
	Tool          string `json:"tool"`
	TemplateID    string `json:"template_id"`
	TemplateName  string `json:"template_name"`
	Severity      string `json:"severity"` // critical | high | medium | low | info
	Type          string `json:"type"`     // http | dns | tcp | ...
	URL           string `json:"url"`
	Host          string `json:"host"`
	Matched       string `json:"matched,omitempty"`
	Description   string `json:"description,omitempty"`
	Reference     []string `json:"reference,omitempty"`
	CVE           []string `json:"cve,omitempty"`
	CWE           []string `json:"cwe,omitempty"`
	CVSS          float64  `json:"cvss,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

type ScanStats struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type errEnv struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// ── globals ────────────────────────────────────────────────────────────

var (
	mu       sync.RWMutex
	scans    = map[string]*Scan{}

	scanSem  = make(chan struct{}, 4) // bounded queue (init in main from -parallel)
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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}
func newID(prefix string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())))
	return prefix + "-" + hex.EncodeToString(h[:6])
}
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(truncated)"
}

// ── persistence ────────────────────────────────────────────────────────

func loadStore() {
	b, err := os.ReadFile(*storePath)
	if err != nil {
		return
	}
	var s struct {
		Scans map[string]*Scan `json:"scans"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		log.Printf("[store] corrupt: %v", err)
		return
	}
	mu.Lock()
	if s.Scans != nil {
		scans = s.Scans
		// Mark any "running" or "queued" scans as "interrupted" — boot recovery
		for _, sc := range scans {
			if sc.Status == "running" || sc.Status == "queued" {
				sc.Status = "failed"
				sc.Error = "interrupted (server restart)"
			}
		}
	}
	mu.Unlock()
	log.Printf("[store] loaded %d scans", len(s.Scans))
}

func persistStore() {
	mu.RLock()
	out := map[string]any{"scans": scans}
	b, _ := json.MarshalIndent(out, "", "  ")
	mu.RUnlock()
	tmp := *storePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		log.Printf("[store] write: %v", err)
		return
	}
	_ = os.Rename(tmp, *storePath)
}

func saveScan(s *Scan) {
	mu.Lock()
	scans[s.ID] = s
	// trim oldest
	if len(scans) > *maxScans {
		var ids []string
		var times []time.Time
		for k, v := range scans {
			ids = append(ids, k)
			times = append(times, v.StartedAt)
		}
		// remove oldest
		oldest := ids[0]; oldestTime := times[0]
		for i, t := range times {
			if t.Before(oldestTime) {
				oldest = ids[i]; oldestTime = t
			}
		}
		delete(scans, oldest)
	}
	mu.Unlock()
	go persistStore()
}

// ── tool detection ─────────────────────────────────────────────────────

type toolStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
}

func detectNuclei() toolStatus {
	path, err := exec.LookPath(*nucleiBin)
	if err != nil {
		return toolStatus{Name: "nuclei", Available: false}
	}
	out, _ := exec.Command(path, "-version").CombinedOutput()
	v := strings.TrimSpace(string(out))
	// extract first line
	if i := strings.Index(v, "\n"); i > 0 {
		v = v[:i]
	}
	return toolStatus{Name: "nuclei", Available: true, Path: path, Version: clip(v, 80)}
}

// ── handlers ───────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	total := len(scans)
	running := 0
	for _, s := range scans {
		if s.Status == "running" {
			running++
		}
	}
	mu.RUnlock()
	t := detectNuclei()
	writeJSON(w, 200, map[string]any{
		"status":       "ok",
		"scans":        total,
		"running":      running,
		"max_parallel": cap(scanSem),
		"tools":        []toolStatus{t},
		"server_time":  time.Now().UTC(),
	})
}

func handleToolsCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"tools": []toolStatus{detectNuclei()},
	})
}

type scanReq struct {
	Target  string `json:"target"`
	Profile string `json:"profile,omitempty"`
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", "")
		return
	}
	var req scanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json", err.Error())
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		writeErr(w, 400, "target required", "e.g. https://example.com")
		return
	}
	if !strings.HasPrefix(req.Target, "http://") && !strings.HasPrefix(req.Target, "https://") {
		writeErr(w, 400, "target must start with http:// or https://", req.Target)
		return
	}
	if _, err := url.Parse(req.Target); err != nil {
		writeErr(w, 400, "invalid URL", err.Error())
		return
	}
	profile := req.Profile
	if profile == "" {
		profile = "quick"
	}
	switch profile {
	case "quick", "standard", "deep":
	default:
		writeErr(w, 400, "unknown profile", "use: quick | standard | deep")
		return
	}

	// Verify nuclei available
	t := detectNuclei()
	if !t.Available {
		writeErr(w, 503, "nuclei not on PATH",
			"install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates")
		return
	}

	scan := &Scan{
		ID:        newID("dast"),
		Target:    req.Target,
		Profile:   profile,
		Status:    "queued",
		Tool:      "nuclei",
		StartedAt: time.Now().UTC(),
	}
	saveScan(scan)

	go runScan(scan)

	writeJSON(w, 202, map[string]any{
		"status":  "queued",
		"id":      scan.ID,
		"target":  scan.Target,
		"profile": scan.Profile,
	})
}

func handleScansList(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	out := make([]*Scan, 0, len(scans))
	for _, s := range scans {
		// Make a copy without findings (large)
		c := *s
		c.Findings = nil
		c.RawOutput = ""
		out = append(out, &c)
	}
	mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	writeJSON(w, 200, map[string]any{"total": len(out), "scans": out})
}

func handleScanOne(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/scans/")
	if rest == "" {
		handleScansList(w, r)
		return
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		id := rest[:i]
		sub := rest[i+1:]
		mu.RLock()
		s, ok := scans[id]
		mu.RUnlock()
		if !ok {
			writeErr(w, 404, "scan not found", id)
			return
		}
		switch sub {
		case "findings":
			writeJSON(w, 200, map[string]any{
				"scan_id":  id,
				"total":    len(s.Findings),
				"findings": s.Findings,
				"stats":    s.Stats,
			})
		case "cancel":
			if r.Method != http.MethodPost {
				writeErr(w, 405, "POST only", "")
				return
			}
			mu.Lock()
			if s.cancel != nil && s.Status == "running" {
				s.cancel()
				s.Status = "cancelled"
			}
			mu.Unlock()
			go persistStore()
			writeJSON(w, 200, map[string]any{"status": "cancel-requested", "id": id})
		default:
			writeErr(w, 404, "unknown sub", sub)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		mu.RLock()
		s, ok := scans[rest]
		mu.RUnlock()
		if !ok {
			writeErr(w, 404, "scan not found", rest)
			return
		}
		writeJSON(w, 200, s)
	case http.MethodDelete:
		mu.Lock()
		_, ok := scans[rest]
		delete(scans, rest)
		mu.Unlock()
		if !ok {
			writeErr(w, 404, "scan not found", rest)
			return
		}
		go persistStore()
		writeJSON(w, 200, map[string]any{"status": "deleted", "id": rest})
	default:
		writeErr(w, 405, "method not allowed", r.Method)
	}
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()
	total := len(scans)
	totalFindings := 0
	stats := ScanStats{}
	running, done, failed := 0, 0, 0
	since24 := time.Now().Add(-24 * time.Hour)
	last24 := 0
	for _, s := range scans {
		totalFindings += len(s.Findings)
		stats.Critical += s.Stats.Critical
		stats.High += s.Stats.High
		stats.Medium += s.Stats.Medium
		stats.Low += s.Stats.Low
		stats.Info += s.Stats.Info
		switch s.Status {
		case "running":
			running++
		case "done":
			done++
		case "failed", "cancelled":
			failed++
		}
		if s.StartedAt.After(since24) {
			last24++
		}
	}
	writeJSON(w, 200, map[string]any{
		"scans_total":   total,
		"scans_24h":     last24,
		"scans_running": running,
		"scans_done":    done,
		"scans_failed":  failed,
		"findings":      totalFindings,
		"by_severity":   stats,
		"server_time":   time.Now().UTC(),
	})
}

// ── scan runner ────────────────────────────────────────────────────────

func runScan(s *Scan) {
	scanSem <- struct{}{}
	defer func() { <-scanSem }()

	mu.Lock()
	if s.Status == "cancelled" {
		mu.Unlock()
		return
	}
	s.Status = "running"
	s.StartedAt = time.Now().UTC()
	mu.Unlock()
	go persistStore()

	args := buildNucleiArgs(s)

	ctx, cancel := context.WithTimeout(context.Background(), profileTimeout(s.Profile))
	defer cancel()

	mu.Lock()
	s.cancel = cancel
	mu.Unlock()

	cmd := exec.CommandContext(ctx, *nucleiBin, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		finishWithError(s, "stdout pipe: "+err.Error())
		return
	}
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		finishWithError(s, "exec start: "+err.Error())
		return
	}

	findings := []Finding{}
	stats := ScanStats{}

	dec := json.NewDecoder(stdout)
	for {
		var ev nucleiEvent
		if err := dec.Decode(&ev); err != nil {
			if err == io.EOF {
				break
			}
			// parse error → skip
			break
		}
		f := nucleiToFinding(ev)
		findings = append(findings, f)
		stats.Total++
		switch f.Severity {
		case "critical":
			stats.Critical++
		case "high":
			stats.High++
		case "medium":
			stats.Medium++
		case "low":
			stats.Low++
		default:
			stats.Info++
		}
		// update progressively (allows live polling)
		mu.Lock()
		s.Findings = findings
		s.Stats = stats
		mu.Unlock()
	}

	waitErr := cmd.Wait()
	mu.Lock()
	s.FinishedAt = time.Now().UTC()
	s.DurationMs = s.FinishedAt.Sub(s.StartedAt).Milliseconds()
	s.RawOutput = clip(stderrBuf.String(), 8192)
	if s.Status == "cancelled" {
		mu.Unlock()
		go persistStore()
		log.Printf("[scan] %s cancelled", s.ID)
		return
	}
	if waitErr != nil && ctx.Err() == context.DeadlineExceeded {
		s.Status = "failed"
		s.Error = "timeout: " + waitErr.Error()
	} else if waitErr != nil && len(findings) == 0 {
		// nuclei returns non-zero exit when it found nothing on some versions
		s.Status = "done"
	} else {
		s.Status = "done"
	}
	mu.Unlock()
	go persistStore()
	log.Printf("[scan] %s '%s' → %s (%d findings, %dms)",
		s.ID, s.Target, s.Status, len(findings), s.DurationMs)
}

func finishWithError(s *Scan, msg string) {
	mu.Lock()
	s.Status = "failed"
	s.Error = msg
	s.FinishedAt = time.Now().UTC()
	s.DurationMs = s.FinishedAt.Sub(s.StartedAt).Milliseconds()
	mu.Unlock()
	go persistStore()
	log.Printf("[scan] %s FAILED: %s", s.ID, msg)
}

func buildNucleiArgs(s *Scan) []string {
	args := []string{
		"-u", s.Target,
		"-jsonl",                  // JSON-lines output
		"-silent",                 // no banner
		"-disable-update-check",
		"-no-interactsh",
		"-rate-limit", "150",
		"-c", "25",                // concurrency
	}
	switch s.Profile {
	case "quick":
		args = append(args, "-severity", "critical,high")
		args = append(args, "-tags", "cve")
	case "standard":
		args = append(args, "-severity", "critical,high,medium")
	case "deep":
		// no -severity filter — full breadth
		args = append(args, "-severity", "critical,high,medium,low")
	}
	return args
}

func profileTimeout(profile string) time.Duration {
	switch profile {
	case "quick":
		return 2 * time.Minute
	case "standard":
		return 8 * time.Minute
	case "deep":
		return 30 * time.Minute
	}
	return 5 * time.Minute
}

// ── nuclei JSON parser ─────────────────────────────────────────────────

type nucleiEvent struct {
	TemplateID  string `json:"template-id"`
	Info        struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Reference   []string `json:"reference"`
		Tags        []string `json:"tags"`
		Classification struct {
			CVE  []string `json:"cve-id"`
			CWE  []string `json:"cwe-id"`
			CVSS float64  `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
	Type     string    `json:"type"`
	Host     string    `json:"host"`
	URL      string    `json:"url"`
	MatchedAt string   `json:"matched-at"`
	Timestamp time.Time `json:"timestamp"`
}

func nucleiToFinding(e nucleiEvent) Finding {
	matched := e.MatchedAt
	if matched == "" {
		matched = e.URL
	}
	host := e.Host
	if host == "" {
		if u, err := url.Parse(e.URL); err == nil {
			host = u.Host
		}
	}
	return Finding{
		Tool:         "nuclei",
		TemplateID:   e.TemplateID,
		TemplateName: e.Info.Name,
		Severity:     strings.ToLower(e.Info.Severity),
		Type:         e.Type,
		URL:          e.URL,
		Host:         host,
		Matched:      matched,
		Description:  e.Info.Description,
		Reference:    e.Info.Reference,
		CVE:          e.Info.Classification.CVE,
		CWE:          e.Info.Classification.CWE,
		CVSS:         e.Info.Classification.CVSS,
		Tags:         e.Info.Tags,
		Timestamp:    e.Timestamp,
	}
}

// ── boot ───────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	// Re-init semaphore with configured max parallel
	scanSem = make(chan struct{}, *maxParallel)

	_ = os.MkdirAll(filepath.Dir(*storePath), 0o770)
	loadStore()

	t := detectNuclei()
	if t.Available {
		log.Printf("[boot] nuclei available: %s — %s", t.Path, t.Version)
	} else {
		log.Printf("[boot] WARN: nuclei NOT on PATH — scans will fail until installed")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz",      cors(handleHealth))
	mux.HandleFunc("/tools/check",  cors(handleToolsCheck))
	mux.HandleFunc("/scan",         cors(handleScan))
	mux.HandleFunc("/scans",        cors(handleScansList))
	mux.HandleFunc("/scans/",       cors(handleScanOne))
	mux.HandleFunc("/stats",        cors(handleStats))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("[vsp-dast-api] listening on %s — parallel=%d store=%s",
		*addr, *maxParallel, *storePath)
	log.Fatal(srv.ListenAndServe())
}
