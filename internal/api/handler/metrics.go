package handler

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	RunsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsp_runs_total",
		Help: "Total scan runs by mode and gate decision",
	}, []string{"mode", "gate"})

	FindingsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsp_findings_total",
		Help: "Total findings by severity and tool",
	}, []string{"severity", "tool"})

	RunDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vsp_run_duration_seconds",
		Help:    "Scan run duration in seconds",
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300},
	}, []string{"mode"})

	ActiveRuns = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vsp_active_runs",
		Help: "Currently running scans",
	})

	HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsp_http_requests_total",
		Help: "Total HTTP requests",
	}, []string{"method", "path", "status"})
)

// MetricsHandler returns the Prometheus metrics endpoint handler.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
