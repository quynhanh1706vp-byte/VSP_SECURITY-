// =====================================================================
// H3.W Telemetry tests
// Place at: internal/telemetry/telemetry_test.go
// =====================================================================

package telemetry

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// =====================================================================
// Label-key canonicalization (critical for series identity)
// =====================================================================

func TestMakeLabelKey_SortsKeys(t *testing.T) {
	// Same labels in different order → same key
	a := makeLabelKey(map[string]string{"a": "1", "b": "2", "c": "3"})
	b := makeLabelKey(map[string]string{"c": "3", "a": "1", "b": "2"})
	if a != b {
		t.Errorf("non-deterministic label key: %q vs %q", a, b)
	}
	if string(a) != "a=1,b=2,c=3" {
		t.Errorf("unexpected canonical form: %q", a)
	}
}

func TestMakeLabelKey_Empty(t *testing.T) {
	if got := makeLabelKey(nil); got != "" {
		t.Errorf("nil → %q want empty", got)
	}
	if got := makeLabelKey(map[string]string{}); got != "" {
		t.Errorf("empty map → %q want empty", got)
	}
}

func TestLabelKey_PromFormat(t *testing.T) {
	lk := makeLabelKey(map[string]string{"method": "GET", "status": "200"})
	got := lk.toPromFormat()
	// Order must match canonical (sorted) order
	if got != `{method="GET",status="200"}` {
		t.Errorf("got %s", got)
	}
}

func TestLabelKey_PromFormat_EscapesQuotes(t *testing.T) {
	lk := makeLabelKey(map[string]string{"msg": `hello "world"`})
	got := lk.toPromFormat()
	if !strings.Contains(got, `\"world\"`) {
		t.Errorf("did not escape quotes: %s", got)
	}
}

// =====================================================================
// Counter behavior
// =====================================================================

func TestCounter_IncrementsAtomically(t *testing.T) {
	r := &Registry{}
	r.Describe("test_counter", "test", "counter")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.CounterInc("test_counter", map[string]string{"k": "v"})
		}()
	}
	wg.Wait()

	// Verify the value
	smAny, ok := r.counters.Load("test_counter")
	if !ok {
		t.Fatal("counter series not stored")
	}
	cAny, _ := smAny.(*sync.Map).Load(makeLabelKey(map[string]string{"k": "v"}))
	if cAny.(*counterSeries).value != 100 {
		t.Errorf("expected 100 increments, got %d", cAny.(*counterSeries).value)
	}
}

func TestCounter_DistinctLabelSeries(t *testing.T) {
	r := &Registry{}
	r.CounterInc("api_hits", map[string]string{"route": "/a"})
	r.CounterInc("api_hits", map[string]string{"route": "/a"})
	r.CounterInc("api_hits", map[string]string{"route": "/b"})

	smAny, _ := r.counters.Load("api_hits")
	sm := smAny.(*sync.Map)
	count := 0
	sm.Range(func(_, _ any) bool { count++; return true })
	if count != 2 {
		t.Errorf("expected 2 distinct series, got %d", count)
	}
}

// =====================================================================
// Histogram behavior
// =====================================================================

func TestHistogram_Buckets(t *testing.T) {
	r := &Registry{}
	r.HistogramObserve("dur_seconds", 0.05, nil)  // falls in 0.05 bucket
	r.HistogramObserve("dur_seconds", 0.5, nil)   // 0.5 bucket
	r.HistogramObserve("dur_seconds", 100.0, nil) // +Inf only

	smAny, _ := r.histograms.Load("dur_seconds")
	hAny, _ := smAny.(*sync.Map).Load(labelKey(""))
	h := hAny.(*histSeries)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count != 3 {
		t.Errorf("expected 3 observations, got %d", h.count)
	}
	// +Inf bucket (last) must be 3
	last := h.buckets[len(h.buckets)-1]
	if last != 3 {
		t.Errorf("expected +Inf=3, got %d", last)
	}
	// 0.005 bucket should be 0 (no values <=0.005)
	if h.buckets[0] != 0 {
		t.Errorf("0.005 bucket should be 0, got %d", h.buckets[0])
	}
}

// =====================================================================
// /metrics endpoint format
// =====================================================================

func TestMetricsEndpoint_PromFormat(t *testing.T) {
	r := &Registry{}
	r.Describe("widgets_total", "Number of widgets", "counter")
	r.CounterAdd("widgets_total", map[string]string{"color": "red"}, 7)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))

	body := rr.Body.String()
	// Required Prometheus format pieces
	expected := []string{
		"# HELP widgets_total",
		"# TYPE widgets_total counter",
		`widgets_total{color="red"} 7`,
	}
	for _, want := range expected {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in output:\n%s", want, body)
		}
	}
}

func TestMetricsEndpoint_HistogramFormat(t *testing.T) {
	r := &Registry{}
	r.Describe("req_dur_seconds", "Request duration", "histogram")
	r.HistogramObserve("req_dur_seconds", 0.05, map[string]string{"route": "/x"})
	r.HistogramObserve("req_dur_seconds", 0.5, map[string]string{"route": "/x"})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()

	// Must emit _bucket, _sum, _count
	must := []string{
		"req_dur_seconds_bucket",
		"req_dur_seconds_sum",
		"req_dur_seconds_count",
		`le="+Inf"`,
	}
	for _, m := range must {
		if !strings.Contains(body, m) {
			t.Errorf("missing %q in histogram output:\n%s", m, body)
		}
	}
}

func TestMetricsEndpoint_RejectsPOST(t *testing.T) {
	r := &Registry{}
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest("POST", "/metrics", nil))
	if rr.Code != 405 {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// =====================================================================
// Tracing — ID generation
// =====================================================================

func TestGenTraceID_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := genTraceID()
		if len(id) != 32 {
			t.Errorf("trace id wrong length: %d (%q)", len(id), id)
		}
		if seen[id] {
			t.Errorf("collision: %q", id)
		}
		seen[id] = true
	}
}

func TestGenSpanID_Length(t *testing.T) {
	id := genSpanID()
	if len(id) != 16 {
		t.Errorf("span id wrong length: %d", len(id))
	}
}

// =====================================================================
// JSON label encoding for DB rows
// =====================================================================

func TestLabelKeyToJSON(t *testing.T) {
	got := labelKeyToJSON("method=GET,status=200")
	// Should be valid JSON object
	if !strings.Contains(got, `"method":"GET"`) || !strings.Contains(got, `"status":"200"`) {
		t.Errorf("bad JSON: %s", got)
	}
	if labelKeyToJSON("") != "{}" {
		t.Errorf("empty label key should produce {}")
	}
}
