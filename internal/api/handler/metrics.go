package handler

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ── VSP custom Prometheus metrics ───────────────────────────────────────────

var (
	ScansTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsp_scans_total",
		Help: "Total number of scans triggered, by mode and status.",
	}, []string{"mode", "status"})

	ScanDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vsp_scan_duration_seconds",
		Help:    "Scan duration in seconds.",
		Buckets: []float64{5, 15, 30, 60, 120, 300, 600},
	}, []string{"mode", "profile"})

	FindingsGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vsp_findings_current",
		Help: "Current finding counts by severity.",
	}, []string{"severity"})

	GateDecisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsp_gate_decisions_total",
		Help: "Gate decisions by outcome.",
	}, []string{"decision"})

	ActiveSSEClients = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vsp_sse_clients_active",
		Help: "Number of active SSE connections.",
	})

	DBPoolConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vsp_db_pool_connections",
		Help: "Database connection pool stats.",
	}, []string{"state"}) // state: total, acquired, idle

	APIRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vsp_api_request_duration_seconds",
		Help:    "API request duration.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path", "status"})

	WebhookDeliveries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsp_webhook_deliveries_total",
		Help: "SIEM webhook delivery attempts.",
	}, []string{"type", "status"})
)

// MetricsHandler returns the Prometheus HTTP handler.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// RecordScan is called by the pipeline after a scan completes.
func RecordScan(mode, status string, duration time.Duration) {
	ScansTotal.WithLabelValues(mode, status).Inc()
	ScanDurationSeconds.WithLabelValues(mode, "").Observe(duration.Seconds())
}

// RecordGate records a gate decision.
func RecordGate(decision string) {
	GateDecisions.WithLabelValues(decision).Inc()
}

// RecordFindings updates the current findings gauge.
func RecordFindings(critical, high, medium, low int) {
	FindingsGauge.WithLabelValues("CRITICAL").Set(float64(critical))
	FindingsGauge.WithLabelValues("HIGH").Set(float64(high))
	FindingsGauge.WithLabelValues("MEDIUM").Set(float64(medium))
	FindingsGauge.WithLabelValues("LOW").Set(float64(low))
}

// RecordDBPool updates DB pool metrics.
func RecordDBPool(stats map[string]int32) {
	for k, v := range stats {
		DBPoolConns.WithLabelValues(k).Set(float64(v))
	}
}
