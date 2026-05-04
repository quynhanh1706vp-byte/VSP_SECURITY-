// =====================================================================
// H3.W Telemetry — Prometheus metrics collector
// File: internal/telemetry/metrics.go
// =====================================================================
//
// Pure-stdlib metrics implementation. We do NOT depend on
// prometheus/client_golang to keep the gateway binary lean and the
// supply chain narrow (CMMC SC-12). The /metrics endpoint emits the
// standard Prometheus exposition format v0.0.4.
//
// Storage:
//   - in-memory counters/histograms (atomic ops, no locks on hot path)
//   - background flusher writes to telemetry_counter / telemetry_histogram
//     every 60s for long-term retention + the v_telemetry_recent view
//
// Concurrency: lock-free reads via sync.Map; writes use atomic.AddInt64
//              for counters and a mutex per histogram bucket.

package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =====================================================================
// Metric primitives
// =====================================================================

// labelKey — canonical string form of a label-set, used as map key.
// Format: "k1=v1,k2=v2" with keys sorted ascending.
type labelKey string

func makeLabelKey(labels map[string]string) labelKey {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(labels[k])
	}
	return labelKey(sb.String())
}

// labelKeyToPromLabels — render "k=v,k2=v2" → `k="v",k2="v2"` for Prom format
func (lk labelKey) toPromFormat() string {
	if lk == "" {
		return ""
	}
	parts := strings.Split(string(lk), ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		k := p[:eq]
		v := strings.ReplaceAll(p[eq+1:], `"`, `\"`)
		out = append(out, fmt.Sprintf(`%s="%s"`, k, v))
	}
	return "{" + strings.Join(out, ",") + "}"
}

// Histogram bucket boundaries (seconds) — covers tool calls (ms) → sessions (min)
var defaultBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300,
}

type counterSeries struct {
	value uint64 // atomic
}

type histSeries struct {
	mu      sync.Mutex
	buckets []uint64 // count per bucket boundary, +Inf appended
	sum     float64
	count   uint64
}

func newHistSeries() *histSeries {
	return &histSeries{buckets: make([]uint64, len(defaultBuckets)+1)}
}

func (h *histSeries) observe(v float64) {
	h.mu.Lock()
	for i, b := range defaultBuckets {
		if v <= b {
			h.buckets[i]++
		}
	}
	h.buckets[len(defaultBuckets)]++ // +Inf
	h.sum += v
	h.count++
	h.mu.Unlock()
}

// =====================================================================
// Registry
// =====================================================================

type Registry struct {
	counters   sync.Map // map[string]*sync.Map[labelKey]*counterSeries
	histograms sync.Map // map[string]*sync.Map[labelKey]*histSeries
	descs      sync.Map // map[string]string  — metric → HELP text
	types      sync.Map // map[string]string  — metric → "counter"|"histogram"

	db        *sql.DB
	startedAt time.Time
}

var globalReg = &Registry{startedAt: time.Now()}

// G — global registry accessor
func G() *Registry { return globalReg }

// AttachDB — wire up DB for the periodic flush
func (r *Registry) AttachDB(db *sql.DB) {
	r.db = db
}

// Describe — register HELP text + TYPE for a metric (called once at init)
func (r *Registry) Describe(name, help, kind string) {
	r.descs.Store(name, help)
	r.types.Store(name, kind)
}

// =====================================================================
// Counter API
// =====================================================================

func (r *Registry) CounterInc(name string, labels map[string]string) {
	r.CounterAdd(name, labels, 1)
}

func (r *Registry) CounterAdd(name string, labels map[string]string, delta uint64) {
	lk := makeLabelKey(labels)
	seriesMapAny, _ := r.counters.LoadOrStore(name, &sync.Map{})
	seriesMap := seriesMapAny.(*sync.Map)
	cAny, _ := seriesMap.LoadOrStore(lk, &counterSeries{})
	atomic.AddUint64(&cAny.(*counterSeries).value, delta)

	// Auto-describe if not already
	if _, ok := r.types.Load(name); !ok {
		r.Describe(name, "auto", "counter")
	}
}

// =====================================================================
// Histogram API
// =====================================================================

func (r *Registry) HistogramObserve(name string, seconds float64, labels map[string]string) {
	lk := makeLabelKey(labels)
	seriesMapAny, _ := r.histograms.LoadOrStore(name, &sync.Map{})
	seriesMap := seriesMapAny.(*sync.Map)
	hAny, _ := seriesMap.LoadOrStore(lk, newHistSeries())
	hAny.(*histSeries).observe(seconds)

	if _, ok := r.types.Load(name); !ok {
		r.Describe(name, "auto", "histogram")
	}
}

// =====================================================================
// Span API (delegates to tracing.go for now — implements Telemetry iface)
// =====================================================================

// StartSpan satisfies the agentic.Telemetry interface. Real OTLP emission
// lives in tracing.go; here we just bump a counter for visibility.
func (r *Registry) StartSpan(ctx context.Context, op string, attrs map[string]any) (context.Context, func(int, error)) {
	r.CounterInc("span_started_total", map[string]string{"op": op})
	start := time.Now()
	return ctx, func(status int, err error) {
		dur := time.Since(start).Seconds()
		labels := map[string]string{"op": op}
		if err != nil {
			labels["error"] = "true"
		} else {
			labels["error"] = "false"
		}
		r.HistogramObserve("span_duration_seconds", dur, labels)
		// Defer to tracing.go for OTLP/DB span row (best-effort, fire-and-forget)
		// span row recording delegated to tracer.go (OTLP SDK)
	}
}

// =====================================================================
// /metrics endpoint — Prometheus exposition format
// =====================================================================

func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Snapshot then render — avoids holding any lock during write
	r.renderCounters(w)
	r.renderHistograms(w)
	r.renderProcess(w)
}

func (r *Registry) renderCounters(w http.ResponseWriter) {
	r.counters.Range(func(nameAny, seriesMapAny any) bool {
		name := nameAny.(string)
		help, _ := r.descs.Load(name)
		fmt.Fprintf(w, "# HELP %s %s\n", name, help)
		fmt.Fprintf(w, "# TYPE %s counter\n", name)
		seriesMapAny.(*sync.Map).Range(func(lkAny, cAny any) bool {
			lk := lkAny.(labelKey)
			v := atomic.LoadUint64(&cAny.(*counterSeries).value)
			fmt.Fprintf(w, "%s%s %d\n", name, lk.toPromFormat(), v)
			return true
		})
		return true
	})
}

func (r *Registry) renderHistograms(w http.ResponseWriter) {
	r.histograms.Range(func(nameAny, seriesMapAny any) bool {
		name := nameAny.(string)
		help, _ := r.descs.Load(name)
		fmt.Fprintf(w, "# HELP %s %s\n", name, help)
		fmt.Fprintf(w, "# TYPE %s histogram\n", name)
		seriesMapAny.(*sync.Map).Range(func(lkAny, hAny any) bool {
			lk := lkAny.(labelKey)
			h := hAny.(*histSeries)
			h.mu.Lock()
			defer h.mu.Unlock()
			// Render each bucket
			labelStr := string(lk)
			for i, b := range defaultBuckets {
				bucketLabel := makeBucketLabel(labelStr, fmt.Sprintf("%g", b))
				fmt.Fprintf(w, "%s_bucket%s %d\n", name, bucketLabel, h.buckets[i])
			}
			fmt.Fprintf(w, "%s_bucket%s %d\n", name,
				makeBucketLabel(labelStr, "+Inf"), h.buckets[len(defaultBuckets)])
			fmt.Fprintf(w, "%s_sum%s %g\n", name, lk.toPromFormat(), h.sum)
			fmt.Fprintf(w, "%s_count%s %d\n", name, lk.toPromFormat(), h.count)
			return true
		})
		return true
	})
}

func makeBucketLabel(existing, le string) string {
	leKV := fmt.Sprintf(`le="%s"`, le)
	if existing == "" {
		return "{" + leKV + "}"
	}
	parts := strings.Split(existing, ",")
	out := make([]string, 0, len(parts)+1)
	for _, p := range parts {
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		out = append(out, fmt.Sprintf(`%s="%s"`, p[:eq], strings.ReplaceAll(p[eq+1:], `"`, `\"`)))
	}
	out = append(out, leKV)
	return "{" + strings.Join(out, ",") + "}"
}

func (r *Registry) renderProcess(w http.ResponseWriter) {
	uptime := time.Since(r.startedAt).Seconds()
	fmt.Fprintf(w, "# HELP vsp_uptime_seconds Gateway uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE vsp_uptime_seconds gauge\n")
	fmt.Fprintf(w, "vsp_uptime_seconds %g\n", uptime)
}

// =====================================================================
// Background flusher → telemetry_counter / telemetry_histogram tables
// =====================================================================

// StartFlusher — call once at gateway boot. Stops on ctx.Done().
func (r *Registry) StartFlusher(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.flushOnce(ctx)
			}
		}
	}()
}

func (r *Registry) flushOnce(ctx context.Context) {
	if r.db == nil {
		return
	}
	bucket := time.Now().Truncate(time.Minute)

	// Counters: write current value (cumulative) — query side computes deltas via lag()
	r.counters.Range(func(nameAny, seriesMapAny any) bool {
		name := nameAny.(string)
		seriesMapAny.(*sync.Map).Range(func(lkAny, cAny any) bool {
			lk := lkAny.(labelKey)
			v := atomic.LoadUint64(&cAny.(*counterSeries).value)
			labels := labelKeyToJSON(lk)
			_, err := r.db.ExecContext(ctx, `
				INSERT INTO telemetry_counter (metric_name, label_pairs, value, bucket_minute)
				VALUES ($1, $2::jsonb, $3, $4)
			`, name, labels, float64(v), bucket)
			if err != nil {
				// best-effort
			}
			return true
		})
		return true
	})

	// Histograms: write running sum + count snapshot
	r.histograms.Range(func(nameAny, seriesMapAny any) bool {
		name := nameAny.(string)
		seriesMapAny.(*sync.Map).Range(func(lkAny, hAny any) bool {
			lk := lkAny.(labelKey)
			h := hAny.(*histSeries)
			h.mu.Lock()
			sum, count := h.sum, h.count
			h.mu.Unlock()
			if count == 0 {
				return true
			}
			labels := labelKeyToJSON(lk)
			avgSec := sum / float64(count)
			_, _ = r.db.ExecContext(ctx, `
				INSERT INTO telemetry_histogram (metric_name, label_pairs, value_seconds, bucket_minute)
				VALUES ($1, $2::jsonb, $3, $4)
			`, name, labels, avgSec, bucket)
			return true
		})
		return true
	})
}

func labelKeyToJSON(lk labelKey) string {
	if lk == "" {
		return "{}"
	}
	m := map[string]string{}
	for _, p := range strings.Split(string(lk), ",") {
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		m[p[:eq]] = p[eq+1:]
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// =====================================================================
// Pre-registration of well-known metric descriptors
// =====================================================================

func init() {
	g := G()
	// H3.T agentic
	g.Describe("agentic_turn_total", "Total LLM/tool turns executed by agentic orchestrator", "counter")
	g.Describe("agentic_tool_total", "Total tool invocations broken down by tool name", "counter")
	g.Describe("agentic_tool_duration_seconds", "Duration of individual tool calls in seconds", "histogram")
	g.Describe("agentic_session_duration_seconds", "Wall-clock duration of an agentic session", "histogram")

	// Gateway HTTP
	g.Describe("http_requests_total", "Total HTTP requests handled by the gateway", "counter")
	g.Describe("http_request_duration_seconds", "HTTP request handling time in seconds", "histogram")

	// Tracing
	g.Describe("span_started_total", "Total spans started", "counter")
	g.Describe("span_duration_seconds", "Span duration in seconds", "histogram")

	// Process
	g.Describe("vsp_uptime_seconds", "Gateway uptime in seconds", "gauge")

	// H3.U remediation worker
	g.Describe("remediation_iterations_total", "Worker loop iterations", "counter")
	g.Describe("remediation_items_resolved_total", "Items auto-resolved by SLA worker", "counter")
	g.Describe("remediation_items_inserted_total", "Items auto-inserted from new findings", "counter")
	g.Describe("remediation_errors_total", "Worker errors encountered", "counter")
	g.Describe("remediation_cycle_duration_seconds", "Duration of one worker cycle", "histogram")

	// H3.V SBOM diff + SW inventory
	g.Describe("sbom_diff_requests_total", "SBOM diff endpoint requests", "counter")
	g.Describe("software_inventory_reports_total", "SW Risk agent ingest reports", "counter")
}

// =====================================================================
// HTTP middleware — wrap any handler to record requests + duration
// =====================================================================

// InstrumentHandler — wraps an http.Handler with Prom counter + histogram.
// Use in main.go: mux.Handle("/api/...", telemetry.InstrumentHandler("api", h))
func InstrumentHandler(routeLabel string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		dur := time.Since(start).Seconds()
		labels := map[string]string{
			"route":  routeLabel,
			"method": r.Method,
			"status": fmt.Sprintf("%d", sw.status),
		}
		G().CounterInc("http_requests_total", labels)
		G().HistogramObserve("http_request_duration_seconds", dur, labels)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}
