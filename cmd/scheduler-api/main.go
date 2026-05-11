// cmd/scheduler-api/main.go
//
// VSP Scheduler microservice (port 8092)
// ─────────────────────────────────────────────────────────────────────
// Pure-Go cron scheduler that dispatches jobs to other VSP microservices.
// Production-grade pattern, mirrors cosign-api / sw-inventory:
//   - JSON store, atomic rename
//   - setsid-launchable, no systemd dependency
//   - CORS on, stdlib only
//   - Per-job mutex to prevent overlapping runs of same job
//
// Job types
//
//	scan_image    → POST trivy-api :8090/scan      {"image":target}
//	sign_image    → POST cosign-api :8091/sign     {"image":target}
//	verify_image  → POST cosign-api :8091/verify   {"image":target}
//	attest_image  → POST cosign-api :8091/attest   {"image":target,"predicate":"slsaprovenance"}
//	cve_recheck   → POST sw-inventory :8094/cve-match
//	sbom_export   → emit CycloneDX JSON to /var/lib/vsp/sbom-exports/<ts>.json
//	webhook       → POST arbitrary URL with payload {target}
//
// Endpoints
//
//	GET  /healthz                  liveness + counts
//	GET  /jobs                     list with computed next_run + last_status
//	GET  /jobs/{id}                detail
//	POST /jobs                     create
//	PUT  /jobs/{id}                update
//	DELETE /jobs/{id}              delete
//	POST /jobs/{id}/run            trigger now (returns run_id)
//	POST /jobs/{id}/toggle         enable/disable
//	GET  /jobs/{id}/runs?limit=N   run history per job
//	GET  /runs?limit=N             all runs (for activity heatmap)
//	GET  /runs/{id}                single run detail (full output)
//	GET  /preview?expr=...&n=5     parse cron, return next N fires + description
//	GET  /stats                    KPIs
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	addr      = flag.String("addr", ":8092", "listen address")
	storePath = flag.String("store", "/var/lib/vsp/scheduler.json", "jobs store")
	runsPath  = flag.String("runs", "/var/lib/vsp/scheduler-runs.json", "run history")
	maxRuns   = flag.Int("max-runs", 1000, "keep last N runs in history")
	tickEvery = flag.Duration("tick", 30*time.Second, "engine tick interval")
	seedFlag  = flag.Bool("seed-on-empty", true, "seed default jobs on first boot")
	noEngine  = flag.Bool("no-engine", false, "disable engine (for testing)")
)

// ── targets of dispatch (defaults can be overridden by env) ───────────

var (
	trivyAPI  = envOr("VSP_TRIVY_API", "http://127.0.0.1:8090")
	cosignAPI = envOr("VSP_COSIGN_API", "http://127.0.0.1:8091")
	swInvAPI  = envOr("VSP_SWINV_API", "http://127.0.0.1:8094")
	sbomDir   = envOr("VSP_SBOM_DIR", "/var/lib/vsp/sbom-exports")
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// ── types ─────────────────────────────────────────────────────────────

type Job struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	CronExpr  string    `json:"cron_expr"`
	Target    string    `json:"target"` // e.g. image name, URL, params
	Enabled   bool      `json:"enabled"`
	Owner     string    `json:"owner,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Cached / computed
	LastRunID    string    `json:"last_run_id,omitempty"`
	LastRunAt    time.Time `json:"last_run_at,omitempty"`
	LastStatus   string    `json:"last_status,omitempty"` // pass | fail | warn | running
	LastDuration string    `json:"last_duration,omitempty"`
	RunCount     int       `json:"run_count"`
	SuccessCount int       `json:"success_count"`
}

type Run struct {
	ID         string    `json:"id"`
	JobID      string    `json:"job_id"`
	JobName    string    `json:"job_name"`
	JobType    string    `json:"job_type"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	DurationMs int64     `json:"duration_ms"`
	Status     string    `json:"status"` // pass | fail | warn | running
	Output     string    `json:"output,omitempty"`
	Error      string    `json:"error,omitempty"`
	HTTPCode   int       `json:"http_code,omitempty"`
	Triggered  string    `json:"triggered"` // schedule | manual
}

type errEnv struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// ── globals ───────────────────────────────────────────────────────────

var (
	jobsMu sync.RWMutex
	jobs   = map[string]*Job{}

	runsMu sync.RWMutex
	runs   []Run

	jobLocks   = map[string]*sync.Mutex{}
	jobLocksMu sync.Mutex
)

func jobLock(id string) *sync.Mutex {
	jobLocksMu.Lock()
	defer jobLocksMu.Unlock()
	if m, ok := jobLocks[id]; ok {
		return m
	}
	m := &sync.Mutex{}
	jobLocks[id] = m
	return m
}

// ── helpers ───────────────────────────────────────────────────────────

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
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())))
	return prefix + "-" + hex.EncodeToString(h[:6])
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(truncated)"
}

// ── persistence ───────────────────────────────────────────────────────

func loadStore() {
	b, err := os.ReadFile(*storePath)
	if err != nil {
		return
	}
	var s struct {
		Jobs map[string]*Job `json:"jobs"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		log.Printf("[store] corrupt %s: %v", *storePath, err)
		return
	}
	jobsMu.Lock()
	if s.Jobs != nil {
		jobs = s.Jobs
	}
	jobsMu.Unlock()
	log.Printf("[store] loaded %d jobs", len(s.Jobs))
}

func persistStore() {
	jobsMu.RLock()
	b, _ := json.MarshalIndent(map[string]any{"jobs": jobs}, "", "  ")
	jobsMu.RUnlock()
	tmp := *storePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("[store] write: %v", err)
		return
	}
	_ = os.Rename(tmp, *storePath)
}

func loadRuns() {
	b, err := os.ReadFile(*runsPath)
	if err != nil {
		return
	}
	var s struct {
		Runs []Run `json:"runs"`
	}
	if json.Unmarshal(b, &s) == nil {
		runsMu.Lock()
		runs = s.Runs
		runsMu.Unlock()
		log.Printf("[runs] loaded %d", len(s.Runs))
	}
}

func persistRuns() {
	runsMu.RLock()
	b, _ := json.MarshalIndent(map[string]any{"runs": runs}, "", "  ")
	runsMu.RUnlock()
	tmp := *runsPath + ".tmp"
	_ = os.WriteFile(tmp, b, 0o600)
	_ = os.Rename(tmp, *runsPath)
}

func appendRun(r Run) {
	runsMu.Lock()
	runs = append(runs, r)
	if len(runs) > *maxRuns {
		runs = runs[len(runs)-*maxRuns:]
	}
	runsMu.Unlock()
	go persistRuns()
}

func updateRun(id string, mut func(*Run)) {
	runsMu.Lock()
	defer runsMu.Unlock()
	for i := range runs {
		if runs[i].ID == id {
			mut(&runs[i])
			break
		}
	}
	go persistRuns()
}

// ── seeded jobs ───────────────────────────────────────────────────────

func seedDefaults() {
	now := time.Now().UTC()
	defaults := []*Job{
		{
			ID:        "job-seed-trivy-nightly",
			Name:      "Nightly Trivy scan",
			Type:      "scan_image",
			CronExpr:  "0 2 * * *",
			Target:    "nginx:1.25-alpine",
			Enabled:   true,
			Notes:     "Scans nginx:1.25-alpine every night at 02:00. Auto-seeded.",
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID:        "job-seed-cve-recheck",
			Name:      "Daily CVE re-match",
			Type:      "cve_recheck",
			CronExpr:  "0 3 * * *",
			Target:    "",
			Enabled:   true,
			Notes:     "Re-runs CVE correlation on all hosts daily at 03:00. Auto-seeded.",
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID:        "job-seed-sbom-weekly",
			Name:      "Weekly SBOM export",
			Type:      "sbom_export",
			CronExpr:  "0 4 * * 0",
			Target:    "all",
			Enabled:   true,
			Notes:     "Exports CycloneDX SBOM every Sunday at 04:00. Auto-seeded.",
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID:        "job-seed-cosign-verify",
			Name:      "Hourly Cosign verify (alpine)",
			Type:      "verify_image",
			CronExpr:  "0 * * * *",
			Target:    "localhost:5000/vsp/alpine:3.19",
			Enabled:   true,
			Notes:     "Verifies signed alpine image every hour. Auto-seeded.",
			CreatedAt: now, UpdatedAt: now,
		},
	}
	jobsMu.Lock()
	added := 0
	for _, j := range defaults {
		if _, ok := jobs[j.ID]; !ok {
			jobs[j.ID] = j
			added++
		}
	}
	jobsMu.Unlock()
	if added > 0 {
		log.Printf("[seed] added %d default jobs (enabled by default)", added)
		go persistStore()
	}
}

// ── handlers ──────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	jobsMu.RLock()
	enabled := 0
	for _, j := range jobs {
		if j.Enabled {
			enabled++
		}
	}
	total := len(jobs)
	jobsMu.RUnlock()
	runsMu.RLock()
	rc := len(runs)
	runsMu.RUnlock()
	writeJSON(w, 200, map[string]any{
		"status":      "ok",
		"jobs":        total,
		"enabled":     enabled,
		"runs":        rc,
		"engine":      !*noEngine,
		"server_time": time.Now().UTC(),
	})
}

func handleJobsList(w http.ResponseWriter, r *http.Request) {
	jobsMu.RLock()
	out := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, jobToMap(j))
	}
	jobsMu.RUnlock()
	sort.Slice(out, func(i, k int) bool {
		return out[i]["name"].(string) < out[k]["name"].(string)
	})
	writeJSON(w, 200, map[string]any{"total": len(out), "jobs": out})
}

func jobToMap(j *Job) map[string]any {
	var nextRun time.Time
	desc := ""
	if c, err := Parse(j.CronExpr); err == nil {
		nextRun = c.Next(time.Now())
		desc = c.Describe()
	}
	return map[string]any{
		"id":            j.ID,
		"name":          j.Name,
		"type":          j.Type,
		"cron_expr":     j.CronExpr,
		"cron_describe": desc,
		"target":        j.Target,
		"enabled":       j.Enabled,
		"owner":         j.Owner,
		"notes":         j.Notes,
		"created_at":    j.CreatedAt,
		"updated_at":    j.UpdatedAt,
		"last_run_id":   j.LastRunID,
		"last_run_at":   j.LastRunAt,
		"last_status":   j.LastStatus,
		"last_duration": j.LastDuration,
		"next_run":      nextRun,
		"run_count":     j.RunCount,
		"success_count": j.SuccessCount,
		"success_rate":  computeRate(j),
	}
}

func computeRate(j *Job) float64 {
	if j.RunCount == 0 {
		return 0
	}
	return float64(j.SuccessCount) / float64(j.RunCount) * 100.0
}

func handleJobsCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed", "")
		return
	}
	defer r.Body.Close()
	var j Job
	if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
		writeErr(w, 400, "bad json", err.Error())
		return
	}
	if err := validateJob(&j); err != nil {
		writeErr(w, 400, "validation", err.Error())
		return
	}
	now := time.Now().UTC()
	j.ID = newID("job")
	j.CreatedAt = now
	j.UpdatedAt = now
	jobsMu.Lock()
	jobs[j.ID] = &j
	jobsMu.Unlock()
	go persistStore()
	writeJSON(w, 201, jobToMap(&j))
}

func handleJobOne(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/jobs/")
	if rest == "" {
		if r.Method == http.MethodPost {
			handleJobsCreate(w, r)
			return
		}
		handleJobsList(w, r)
		return
	}
	// Sub-paths: {id}/run, {id}/toggle, {id}/runs
	if i := strings.Index(rest, "/"); i >= 0 {
		id := rest[:i]
		sub := rest[i+1:]
		switch sub {
		case "run":
			if r.Method != http.MethodPost {
				writeErr(w, 405, "POST only", "")
				return
			}
			handleJobRun(w, r, id, "manual")
			return
		case "toggle":
			if r.Method != http.MethodPost {
				writeErr(w, 405, "POST only", "")
				return
			}
			handleJobToggle(w, r, id)
			return
		case "runs":
			handleJobRunsList(w, r, id)
			return
		default:
			writeErr(w, 404, "unknown sub-resource", sub)
			return
		}
	}
	// /jobs/{id}
	switch r.Method {
	case http.MethodGet:
		jobsMu.RLock()
		j, ok := jobs[rest]
		jobsMu.RUnlock()
		if !ok {
			writeErr(w, 404, "not found", rest)
			return
		}
		writeJSON(w, 200, jobToMap(j))
	case http.MethodPut:
		var u Job
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			writeErr(w, 400, "bad json", err.Error())
			return
		}
		jobsMu.Lock()
		j, ok := jobs[rest]
		if !ok {
			jobsMu.Unlock()
			writeErr(w, 404, "not found", rest)
			return
		}
		// Mutable fields
		if u.Name != "" {
			j.Name = u.Name
		}
		if u.CronExpr != "" {
			if _, err := Parse(u.CronExpr); err != nil {
				jobsMu.Unlock()
				writeErr(w, 400, "invalid cron", err.Error())
				return
			}
			j.CronExpr = u.CronExpr
		}
		if u.Type != "" {
			j.Type = u.Type
		}
		j.Target = u.Target
		j.Notes = u.Notes
		j.Owner = u.Owner
		j.Enabled = u.Enabled
		j.UpdatedAt = time.Now().UTC()
		jobsMu.Unlock()
		go persistStore()
		writeJSON(w, 200, jobToMap(j))
	case http.MethodDelete:
		jobsMu.Lock()
		_, ok := jobs[rest]
		delete(jobs, rest)
		jobsMu.Unlock()
		if !ok {
			writeErr(w, 404, "not found", rest)
			return
		}
		go persistStore()
		writeJSON(w, 200, map[string]any{"status": "deleted", "id": rest})
	default:
		writeErr(w, 405, "method not allowed", r.Method)
	}
}

func handleJobToggle(w http.ResponseWriter, r *http.Request, id string) {
	jobsMu.Lock()
	j, ok := jobs[id]
	if !ok {
		jobsMu.Unlock()
		writeErr(w, 404, "not found", id)
		return
	}
	j.Enabled = !j.Enabled
	j.UpdatedAt = time.Now().UTC()
	jobsMu.Unlock()
	go persistStore()
	writeJSON(w, 200, map[string]any{"id": id, "enabled": j.Enabled})
}

func validateJob(j *Job) error {
	j.Name = strings.TrimSpace(j.Name)
	if j.Name == "" {
		return fmt.Errorf("name required")
	}
	if j.CronExpr == "" {
		return fmt.Errorf("cron_expr required")
	}
	if _, err := Parse(j.CronExpr); err != nil {
		return fmt.Errorf("invalid cron: %v", err)
	}
	switch j.Type {
	case "scan_image", "sign_image", "verify_image", "attest_image",
		"cve_recheck", "sbom_export", "webhook":
		// ok
	case "":
		return fmt.Errorf("type required")
	default:
		return fmt.Errorf("unknown type: %s", j.Type)
	}
	return nil
}

func handleJobRun(w http.ResponseWriter, r *http.Request, id, trigger string) {
	jobsMu.RLock()
	j, ok := jobs[id]
	jobsMu.RUnlock()
	if !ok {
		writeErr(w, 404, "not found", id)
		return
	}
	run := startRun(j, trigger)
	writeJSON(w, 202, map[string]any{
		"status":  "started",
		"run_id":  run.ID,
		"job_id":  id,
		"started": run.StartedAt,
	})
}

func handleJobRunsList(w http.ResponseWriter, r *http.Request, id string) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	runsMu.RLock()
	out := make([]Run, 0, limit)
	for i := len(runs) - 1; i >= 0 && len(out) < limit; i-- {
		if runs[i].JobID == id {
			out = append(out, runs[i])
		}
	}
	runsMu.RUnlock()
	writeJSON(w, 200, map[string]any{"total": len(out), "runs": out})
}

func handleAllRuns(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	since := r.URL.Query().Get("since")
	var sinceT time.Time
	if since != "" {
		sinceT, _ = time.Parse(time.RFC3339, since)
	}

	runsMu.RLock()
	out := make([]Run, 0, limit)
	for i := len(runs) - 1; i >= 0 && len(out) < limit; i-- {
		if !sinceT.IsZero() && runs[i].StartedAt.Before(sinceT) {
			break
		}
		out = append(out, runs[i])
	}
	runsMu.RUnlock()
	writeJSON(w, 200, map[string]any{"total": len(out), "runs": out})
}

func handleRunOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/runs/")
	runsMu.RLock()
	defer runsMu.RUnlock()
	for i := range runs {
		if runs[i].ID == id {
			writeJSON(w, 200, runs[i])
			return
		}
	}
	writeErr(w, 404, "run not found", id)
}

func handlePreview(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("expr")
	if expr == "" {
		writeErr(w, 400, "expr required", "")
		return
	}
	n := 5
	if v := r.URL.Query().Get("n"); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x > 0 && x <= 20 {
			n = x
		}
	}
	c, err := Parse(expr)
	if err != nil {
		writeErr(w, 400, "invalid cron", err.Error())
		return
	}
	now := time.Now()
	nexts := c.NextN(now, n)
	out := make([]map[string]any, 0, len(nexts))
	for _, t := range nexts {
		out = append(out, map[string]any{
			"time":    t.Format(time.RFC3339),
			"in":      t.Sub(now).Round(time.Second).String(),
			"weekday": t.Weekday().String(),
		})
	}
	writeJSON(w, 200, map[string]any{
		"expr":     expr,
		"valid":    true,
		"describe": c.Describe(),
		"next":     out,
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	jobsMu.RLock()
	total := len(jobs)
	enabled := 0
	for _, j := range jobs {
		if j.Enabled {
			enabled++
		}
	}
	jobsMu.RUnlock()

	since24 := time.Now().Add(-24 * time.Hour)
	pass24, fail24, warn24 := 0, 0, 0
	runsMu.RLock()
	for _, r := range runs {
		if r.StartedAt.Before(since24) {
			continue
		}
		switch r.Status {
		case "pass":
			pass24++
		case "fail":
			fail24++
		case "warn":
			warn24++
		}
	}
	totalRuns := len(runs)
	runsMu.RUnlock()
	rate := 0.0
	if pass24+fail24+warn24 > 0 {
		rate = float64(pass24) / float64(pass24+fail24+warn24) * 100.0
	}
	writeJSON(w, 200, map[string]any{
		"jobs":        total,
		"enabled":     enabled,
		"runs":        totalRuns,
		"runs_24h":    pass24 + fail24 + warn24,
		"pass_24h":    pass24,
		"fail_24h":    fail24,
		"warn_24h":    warn24,
		"pass_rate":   rate,
		"server_time": time.Now().UTC(),
	})
}

// ── engine ────────────────────────────────────────────────────────────

func engineLoop() {
	ticker := time.NewTicker(*tickEvery)
	defer ticker.Stop()
	log.Printf("[engine] started, tick=%v", *tickEvery)
	for range ticker.C {
		dispatchDue()
	}
}

func dispatchDue() {
	now := time.Now().UTC().Truncate(time.Minute)
	jobsMu.RLock()
	due := make([]*Job, 0)
	for _, j := range jobs {
		if !j.Enabled {
			continue
		}
		c, err := Parse(j.CronExpr)
		if err != nil {
			continue
		}
		if !c.Match(now) {
			continue
		}
		// Skip if already ran this minute
		if !j.LastRunAt.IsZero() && j.LastRunAt.Truncate(time.Minute).Equal(now) {
			continue
		}
		due = append(due, j)
	}
	jobsMu.RUnlock()
	for _, j := range due {
		go startRun(j, "schedule")
	}
}

func startRun(j *Job, trigger string) Run {
	lock := jobLock(j.ID)
	if !lock.TryLock() {
		// Already running — skip, return empty marker
		return Run{Status: "skipped"}
	}

	run := Run{
		ID:        newID("run"),
		JobID:     j.ID,
		JobName:   j.Name,
		JobType:   j.Type,
		StartedAt: time.Now().UTC(),
		Status:    "running",
		Triggered: trigger,
	}
	appendRun(run)

	// Update job's last_status to "running"
	jobsMu.Lock()
	j.LastRunID = run.ID
	j.LastRunAt = run.StartedAt
	j.LastStatus = "running"
	jobsMu.Unlock()

	go func() {
		defer lock.Unlock()
		// Dispatch
		status, output, errStr, code := dispatch(j)
		dur := time.Since(run.StartedAt)

		updateRun(run.ID, func(r *Run) {
			r.FinishedAt = time.Now().UTC()
			r.DurationMs = dur.Milliseconds()
			r.Status = status
			r.Output = clip(output, 8192)
			r.Error = clip(errStr, 1024)
			r.HTTPCode = code
		})

		// Update job
		jobsMu.Lock()
		j.LastStatus = status
		j.LastDuration = dur.Round(time.Millisecond).String()
		j.RunCount++
		if status == "pass" {
			j.SuccessCount++
		}
		jobsMu.Unlock()
		go persistStore()

		log.Printf("[run] %s '%s' → %s in %s", j.Type, j.Name, status, dur)
	}()
	return run
}

// dispatch runs the job synchronously and returns (status, output, error, http_code).
func dispatch(j *Job) (string, string, string, int) {
	switch j.Type {
	case "scan_image":
		return postJSON(trivyAPI+"/scan", map[string]any{"image": j.Target})
	case "sign_image":
		return postJSON(cosignAPI+"/sign", map[string]any{"image": j.Target})
	case "verify_image":
		return postJSONExpect(cosignAPI+"/verify",
			map[string]any{"image": j.Target}, "verified")
	case "attest_image":
		return postJSON(cosignAPI+"/attest",
			map[string]any{"image": j.Target, "predicate": "slsaprovenance"})
	case "cve_recheck":
		return postJSON(swInvAPI+"/cve-match", map[string]any{})
	case "sbom_export":
		return runSBOMExport(j)
	case "webhook":
		return postJSON(j.Target, map[string]any{
			"job":   j.Name,
			"time":  time.Now().UTC(),
			"event": "scheduled-trigger",
		})
	default:
		return "fail", "", "unknown job type: " + j.Type, 0
	}
}

func postJSON(url string, body any) (string, string, string, int) {
	return postJSONExpect(url, body, "")
}

// postJSONExpect: if expectStatus != "", we look at returned JSON's "status"
// field and treat status==expectStatus as pass. Otherwise we use HTTP code.
func postJSONExpect(url string, body any, expectStatus string) (string, string, string, int) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return "fail", "", err.Error(), 0
	}
	req.Header.Set("Content-Type", "application/json")
	cli := &http.Client{Timeout: 90 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return "fail", "", err.Error(), 0
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	output := string(respBody)
	if resp.StatusCode >= 300 {
		return "fail", output, fmt.Sprintf("HTTP %d", resp.StatusCode), resp.StatusCode
	}
	if expectStatus != "" {
		var probe struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(respBody, &probe)
		if probe.Status != expectStatus {
			return "fail", output, fmt.Sprintf("expected status=%s got %q", expectStatus, probe.Status), resp.StatusCode
		}
	}
	return "pass", output, "", resp.StatusCode
}

func runSBOMExport(j *Job) (string, string, string, int) {
	_ = os.MkdirAll(sbomDir, 0o700)
	ts := time.Now().UTC().Format("20060102-150405")
	target := j.Target
	if target == "" || target == "all" {
		target = "all-signed-images"
	}
	out := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.4",
		"serialNumber": "urn:uuid:" + newID("sbom"),
		"version":      1,
		"metadata": map[string]any{
			"timestamp": time.Now().UTC(),
			"tools": []map[string]any{
				{"vendor": "VSP", "name": "vsp-scheduler", "version": "1.0"},
			},
			"component": map[string]any{
				"type": "container",
				"name": target,
			},
		},
		"components": []any{},
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	path := filepath.Join(sbomDir, ts+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "fail", "", err.Error(), 0
	}
	return "pass", fmt.Sprintf("wrote %s (%d bytes)", path, len(b)), "", 200
}

// ── boot ──────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	_ = os.MkdirAll(filepath.Dir(*storePath), 0o700)
	_ = os.MkdirAll(filepath.Dir(*runsPath), 0o700)
	loadStore()
	loadRuns()

	if *seedFlag {
		jobsMu.RLock()
		empty := len(jobs) == 0
		jobsMu.RUnlock()
		if empty {
			seedDefaults()
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", cors(handleHealth))
	mux.HandleFunc("/jobs", cors(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleJobsCreate(w, r)
			return
		}
		handleJobsList(w, r)
	}))
	mux.HandleFunc("/jobs/", cors(handleJobOne))
	mux.HandleFunc("/runs", cors(handleAllRuns))
	mux.HandleFunc("/runs/", cors(handleRunOne))
	mux.HandleFunc("/preview", cors(handlePreview))
	mux.HandleFunc("/stats", cors(handleStats))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if !*noEngine {
		go engineLoop()
	}

	log.Printf("[vsp-scheduler] listening on %s — store=%s", *addr, *storePath)
	log.Fatal(srv.ListenAndServe())
}
