package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vsp/platform/internal/api/handler"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/pipeline"
	"github.com/vsp/platform/internal/store"
)

// ── Structs ───────────────────────────────────────────────────────────────────

type batchScanItem struct {
	Mode    string `json:"mode"`
	Profile string `json:"profile"`
	Src     string `json:"src"`
	Label   string `json:"label"`
}

type batchScanRequest struct {
	Items      []batchScanItem `json:"items"`
	Parallel   int             `json:"parallel"`
	FailFast   bool            `json:"fail_fast"`
	BatchLabel string          `json:"batch_label"`
}

type batchJobStatus struct {
	Index     int        `json:"index"`
	RID       string     `json:"rid"`
	Mode      string     `json:"mode"`
	Profile   string     `json:"profile"`
	Src       string     `json:"src"`
	Label     string     `json:"label"`
	Status    string     `json:"status"`
	Gate      string     `json:"gate"`
	Findings  int        `json:"findings"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	DoneAt    *time.Time `json:"done_at,omitempty"`
	Error     string     `json:"error,omitempty"`
}

type batchRecord struct {
	BatchID   string           `json:"batch_id"`
	TenantID  string           `json:"tenant_id"`
	Label     string           `json:"label"`
	Status    string           `json:"status"`
	Total     int              `json:"total"`
	Done      int              `json:"done"`
	Failed    int              `json:"failed"`
	Passed    int              `json:"passed"`
	Warned    int              `json:"warned"`
	Jobs      []batchJobStatus `json:"jobs"`
	CreatedAt time.Time        `json:"created_at"`
	StartedAt *time.Time       `json:"started_at,omitempty"`
	DoneAt    *time.Time       `json:"done_at,omitempty"`
	Parallel  int              `json:"parallel"`
	FailFast  bool             `json:"fail_fast"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

type batchHandler struct {
	rdb   *batchRedisStore
	db    *store.DB
	pool  *pgxpool.Pool
	runsH *handler.Runs
	// in-memory cache: batch_id → record (avoid DB round-trips on hot polling)
	mu    sync.RWMutex
	cache map[string]*batchRecord
}

func newBatchHandler(db *store.DB, runsH *handler.Runs) *batchHandler {
	return &batchHandler{
		db:    db,
		pool:  db.Pool(),
		runsH: runsH,
		cache: make(map[string]*batchRecord),
	}
}

// ── POST /api/v1/vsp/batch ────────────────────────────────────────────────────

func (h *batchHandler) Submit(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req batchScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Items) == 0 {
		jsonErr(w, "items: min 1 required", http.StatusBadRequest)
		return
	}
	if len(req.Items) > 20 {
		jsonErr(w, "items: max 20 per batch", http.StatusBadRequest)
		return
	}

	parallel := req.Parallel
	if parallel <= 0 {
		parallel = 3
	}
	if parallel > 5 {
		parallel = 5
	}

	batchID := "BATCH_" + uuid.New().String()[:8]

	jobs := make([]batchJobStatus, len(req.Items))
	for i, item := range req.Items {
		mode := item.Mode
		if mode == "" {
			mode = "FULL"
		}
		profile := item.Profile
		if profile == "" {
			profile = "FAST"
		}
		label := item.Label
		if label == "" {
			label = fmt.Sprintf("Job %d — %s", i+1, mode)
		}
		if item.Src == "" {
			jsonErr(w, fmt.Sprintf("item[%d].src is required", i), http.StatusBadRequest)
			return
		}
		if strings.ContainsAny(item.Src, ";&|`$<>{}\\") {
			jsonErr(w, fmt.Sprintf("item[%d].src: contains illegal characters", i), http.StatusBadRequest)
			return
		}
		if len(item.Src) > 500 {
			jsonErr(w, fmt.Sprintf("item[%d].src: too long (max 500)", i), http.StatusBadRequest)
			return
		}
		jobs[i] = batchJobStatus{
			Index: i, Mode: mode, Profile: profile,
			Src: item.Src, Label: label, Status: "QUEUED", Gate: "—",
		}
	}

	label := req.BatchLabel
	if label == "" {
		label = fmt.Sprintf("Batch %s · %d jobs", batchID[6:], len(jobs))
	}

	batch := &batchRecord{
		BatchID: batchID, TenantID: claims.TenantID, Label: label,
		Status: "QUEUED", Total: len(jobs), Jobs: jobs,
		CreatedAt: time.Now(), Parallel: parallel, FailFast: req.FailFast,
	}

	// ── Persist to DB ─────────────────────────────────────────────────────────
	ctx := r.Context()
	_, err := h.pool.Exec(ctx, `
		INSERT INTO batch_runs
		  (batch_id, tenant_id, label, status, total, parallel, fail_fast)
		VALUES ($1,$2,$3,'QUEUED',$4,$5,$6)`,
		batchID, claims.TenantID, label, len(jobs), parallel, req.FailFast,
	)
	if err != nil {
		jsonErr(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for _, job := range jobs {
		h.pool.Exec(ctx, `
			INSERT INTO batch_jobs
			  (batch_id, tenant_id, idx, mode, profile, src, label, status, gate)
			VALUES ($1,$2,$3,$4,$5,$6,$7,'QUEUED','—')`,
			batchID, claims.TenantID, job.Index,
			job.Mode, job.Profile, job.Src, job.Label,
		) //nolint:errcheck
	}

	// Cache + run async
	h.mu.Lock()
	h.cache[batchID] = batch
	h.mu.Unlock()

	// Persist to Redis (survive restart)
	if h.rdb != nil {
		h.rdb.Set(r.Context(), batch) //nolint:errcheck
	}

	go h.runBatch(context.Background(), batchID) //nolint:gosec // G118: batch runs async beyond request lifetime

	jsonOK(w, map[string]any{
		"batch_id":   batchID,
		"total":      len(jobs),
		"parallel":   parallel,
		"message":    fmt.Sprintf("Batch queued: %d jobs, parallel=%d", len(jobs), parallel),
		"status_url": "/api/v1/vsp/batch/" + batchID,
	})
}

// ── runBatch goroutine ────────────────────────────────────────────────────────

func (h *batchHandler) runBatch(ctx context.Context, batchID string) {
	h.mu.Lock()
	batch := h.cache[batchID]
	now := time.Now()
	batch.Status = "RUNNING"
	batch.StartedAt = &now
	h.mu.Unlock()

	h.pool.Exec(ctx, `UPDATE batch_runs SET status='RUNNING', started_at=$1 WHERE batch_id=$2`,
		now, batchID) //nolint:errcheck

	sem := make(chan struct{}, batch.Parallel)
	var wg sync.WaitGroup
	cancelled := false

	for i := range batch.Jobs {
		h.mu.RLock()
		if batch.Status == "CANCELLED" {
			h.mu.RUnlock()
			break
		}
		h.mu.RUnlock()

		if batch.FailFast && cancelled {
			h.mu.Lock()
			for j := i; j < len(batch.Jobs); j++ {
				if batch.Jobs[j].Status == "QUEUED" {
					batch.Jobs[j].Status = "CANCELLED"
					h.pool.Exec(ctx, `UPDATE batch_jobs SET status='CANCELLED' WHERE batch_id=$1 AND idx=$2`,
						batchID, j) //nolint:errcheck
				}
			}
			h.mu.Unlock()
			break
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			h.mu.Lock()
			job := &batch.Jobs[idx]
			t := time.Now()
			job.Status = "RUNNING"
			job.StartedAt = &t
			tenantID := batch.TenantID
			failFast := batch.FailFast
			h.mu.Unlock()

			h.pool.Exec(ctx, `UPDATE batch_jobs SET status='RUNNING', started_at=$1 WHERE batch_id=$2 AND idx=$3`,
				t, batchID, idx) //nolint:errcheck

			rid, gate, findings, err := h.dispatchScan(ctx, tenantID, job.Mode, job.Profile, job.Src)

			h.mu.Lock()
			doneAt := time.Now()
			job.DoneAt = &doneAt
			job.RID = rid

			if err != nil {
				job.Status = "FAILED"
				job.Gate = "—"
				job.Error = err.Error()
				batch.Failed++
				if failFast {
					cancelled = true
				}
			} else {
				job.Status = "DONE"
				job.Gate = gate
				job.Findings = findings
				switch gate {
				case "PASS":
					batch.Passed++
				case "WARN":
					batch.Warned++
				case "FAIL":
					batch.Failed++
					if failFast {
						cancelled = true
					}
				}
			}
			batch.Done++

			// Sync counters to DB
			h.pool.Exec(ctx, `
				UPDATE batch_runs SET
				  done=$1, passed=$2, warned=$3, failed=$4
				WHERE batch_id=$5`,
				batch.Done, batch.Passed, batch.Warned, batch.Failed, batchID,
			) //nolint:errcheck
			h.mu.Unlock()

			// Update job row
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			h.pool.Exec(ctx, `
				UPDATE batch_jobs SET
				  rid=$1, status=$2, gate=$3, findings=$4, error=$5, done_at=$6
				WHERE batch_id=$7 AND idx=$8`,
				rid, job.Status, job.Gate, findings, errStr, doneAt, batchID, idx,
			) //nolint:errcheck
		}(i)
	}

	wg.Wait()

	h.mu.Lock()
	doneAt := time.Now()
	batch.DoneAt = &doneAt
	finalStatus := "DONE"
	if batch.Status == "CANCELLED" {
		finalStatus = "CANCELLED"
	} else if batch.Failed > 0 {
		finalStatus = "FAILED"
	}
	batch.Status = finalStatus
	h.mu.Unlock()

	h.pool.Exec(ctx, `UPDATE batch_runs SET status=$1, done_at=$2 WHERE batch_id=$3`,
		finalStatus, doneAt, batchID) //nolint:errcheck
}

// ── dispatchScan ──────────────────────────────────────────────────────────────

func (h *batchHandler) dispatchScan(ctx context.Context, tenantID, mode, profile, src string) (rid, gate string, findings int, err error) {
	rid = fmt.Sprintf("RID_VSPGO_RUN_%s_%s",
		time.Now().Format("20060102_150405"),
		uuid.New().String()[:8],
	)

	h.runsH.EnqueueDirect(rid, tenantID,
		pipeline.Mode(mode),
		pipeline.Profile(profile),
		src, "",
	)

	// Poll DB với exponential backoff: 1s→2s→4s→8s→16s→30s (max)
	// Tránh DB I/O storm khi nhiều jobs chạy parallel
	deadline := time.Now().Add(10 * time.Minute)
	wait := time.Second
	for time.Now().Before(deadline) {
		time.Sleep(wait)
		// Tăng wait exponentially, max 30s
		if wait < 30*time.Second {
			wait *= 2
			if wait > 30*time.Second {
				wait = 30 * time.Second
			}
		}
		run, dbErr := h.db.GetRunByRID(ctx, tenantID, rid)
		if dbErr != nil || run == nil {
			continue
		}
		switch run.Status {
		case "DONE":
			return rid, run.Gate, run.TotalFindings, nil
		case "FAILED":
			return rid, "FAIL", run.TotalFindings, fmt.Errorf("scan failed: %s", rid)
		case "CANCELLED":
			return rid, "—", 0, fmt.Errorf("scan cancelled: %s", rid)
		}
	}
	return rid, "—", 0, fmt.Errorf("timeout waiting for run %s", rid)
}

// ── GET /api/v1/vsp/batch/{batch_id} ─────────────────────────────────────────

func (h *batchHandler) Status(w http.ResponseWriter, r *http.Request) {
	batchID := chi.URLParam(r, "batch_id")
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Try cache first (hot path during polling)
	h.mu.RLock()
	batch, inCache := h.cache[batchID]
	h.mu.RUnlock()

	if !inCache {
		// Try Redis first (faster than DB)
		if h.rdb != nil {
			if rb, _ := h.rdb.Get(r.Context(), batchID); rb != nil && rb.TenantID == claims.TenantID {
				batch = rb
				h.mu.Lock()
				h.cache[batchID] = rb
				h.mu.Unlock()
				inCache = true
			}
		}
		if !inCache {
			// Fallback: Load from DB
			loaded, err := h.loadFromDB(r.Context(), claims.TenantID, batchID)
			if err != nil || loaded == nil {
				jsonErr(w, "batch not found: "+batchID, http.StatusNotFound)
				return
			}
			batch = loaded
		}
	} else if batch.TenantID != claims.TenantID {
		jsonErr(w, "batch not found: "+batchID, http.StatusNotFound)
		return
	}

	pct := 0
	if batch.Total > 0 {
		pct = batch.Done * 100 / batch.Total
	}
	jsonOK(w, map[string]any{"batch": batch, "progress": pct})
}

// loadFromDB — reconstruct batchRecord từ DB sau restart
func (h *batchHandler) loadFromDB(ctx context.Context, tenantID, batchID string) (*batchRecord, error) {
	row := h.pool.QueryRow(ctx, `
		SELECT batch_id, tenant_id, label, status, total, done,
		       passed, warned, failed, parallel, fail_fast,
		       created_at, started_at, done_at
		FROM batch_runs WHERE batch_id=$1 AND tenant_id=$2`,
		batchID, tenantID)

	var b batchRecord
	err := row.Scan(
		&b.BatchID, &b.TenantID, &b.Label, &b.Status,
		&b.Total, &b.Done, &b.Passed, &b.Warned, &b.Failed,
		&b.Parallel, &b.FailFast,
		&b.CreatedAt, &b.StartedAt, &b.DoneAt,
	)
	if err != nil {
		return nil, err
	}

	// Load jobs
	rows, err := h.pool.Query(ctx, `
		SELECT idx, rid, mode, profile, src, label,
		       status, gate, findings, error, started_at, done_at
		FROM batch_jobs WHERE batch_id=$1 AND tenant_id=$2
		ORDER BY idx`, batchID, tenantID)
	if err != nil {
		return &b, nil
	}
	defer rows.Close()

	for rows.Next() {
		var j batchJobStatus
		_ = rows.Scan(
			&j.Index, &j.RID, &j.Mode, &j.Profile, &j.Src, &j.Label,
			&j.Status, &j.Gate, &j.Findings, &j.Error,
			&j.StartedAt, &j.DoneAt,
		) //nolint:errcheck
		b.Jobs = append(b.Jobs, j)
	}

	// Put into cache
	h.mu.Lock()
	h.cache[batchID] = &b
	h.mu.Unlock()

	return &b, nil
}

// ── DELETE /api/v1/vsp/batch/{batch_id} ──────────────────────────────────────

func (h *batchHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	batchID := chi.URLParam(r, "batch_id")
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Try cache first
	h.mu.Lock()
	batch, exists := h.cache[batchID]
	if !exists {
		// Fallback: Redis
		if h.rdb != nil {
			if rb, _ := h.rdb.Get(r.Context(), batchID); rb != nil && rb.TenantID == claims.TenantID {
				h.cache[batchID] = rb
				batch, exists = rb, true
			}
		}
		// Fallback: DB (post-restart, cache+redis cold)
		if !exists {
			var status, tenantID string
			err := h.pool.QueryRow(r.Context(),
				`SELECT status, tenant_id FROM batch_runs WHERE batch_id=$1`, batchID,
			).Scan(&status, &tenantID)
			if err != nil {
				h.mu.Unlock()
				jsonErr(w, "batch not found", http.StatusNotFound)
				return
			}
			if tenantID != claims.TenantID {
				h.mu.Unlock()
				jsonErr(w, "batch not found", http.StatusNotFound)
				return
			}
			if status == "DONE" || status == "FAILED" {
				h.mu.Unlock()
				jsonErr(w, "batch already finished: "+status, http.StatusBadRequest)
				return
			}
			// Cancel via DB directly — no in-memory record to update
			h.mu.Unlock()
			h.pool.Exec(r.Context(), `UPDATE batch_runs SET status='CANCELLED' WHERE batch_id=$1`, batchID) //nolint:errcheck
			jsonOK(w, map[string]any{
				"batch_id": batchID,
				"message":  "Cancel requested — running jobs finish, queued jobs skipped",
			})
			return
		}
	}

	if batch.TenantID != claims.TenantID {
		h.mu.Unlock()
		jsonErr(w, "batch not found", http.StatusNotFound)
		return
	}
	if batch.Status == "DONE" || batch.Status == "FAILED" {
		h.mu.Unlock()
		jsonErr(w, "batch already finished: "+batch.Status, http.StatusBadRequest)
		return
	}
	batch.Status = "CANCELLED"
	h.mu.Unlock()

	h.pool.Exec(r.Context(), `UPDATE batch_runs SET status='CANCELLED' WHERE batch_id=$1`, batchID) //nolint:errcheck

	jsonOK(w, map[string]any{
		"batch_id": batchID,
		"message":  "Cancel requested — running jobs finish, queued jobs skipped",
	})
}

// ── GET /api/v1/vsp/batches ───────────────────────────────────────────────────

func (h *batchHandler) ListAll(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := h.pool.Query(r.Context(), `
		SELECT batch_id, label, status, total, done, passed, warned, failed,
		       parallel, fail_fast, created_at, started_at, done_at
		FROM batch_runs
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT 100`,
		claims.TenantID,
	)
	if err != nil {
		jsonErr(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	list := make([]map[string]any, 0)
	for rows.Next() {
		var (
			batchID, label, status              string
			total, done, passed, warned, failed int
			parallel                            int
			failFast                            bool
			createdAt                           time.Time
			startedAt, doneAt                   *time.Time
		)
		if err := rows.Scan(
			&batchID, &label, &status,
			&total, &done, &passed, &warned, &failed,
			&parallel, &failFast,
			&createdAt, &startedAt, &doneAt,
		); err != nil {
			continue
		}

		pct := 0
		if total > 0 {
			pct = done * 100 / total
		}

		list = append(list, map[string]any{
			"batch_id":   batchID,
			"label":      label,
			"status":     status,
			"total":      total,
			"done":       done,
			"passed":     passed,
			"warned":     warned,
			"failed":     failed,
			"parallel":   parallel,
			"fail_fast":  failFast,
			"progress":   pct,
			"created_at": createdAt,
			"started_at": startedAt,
			"done_at":    doneAt,
		})
	}

	jsonOK(w, map[string]any{"batches": list, "total": len(list)})
}

// ── JSON helpers ─────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}
