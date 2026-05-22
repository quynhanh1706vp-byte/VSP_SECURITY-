package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/vsp/platform/internal/soar"
)

// SOARPromAdapter implements soar.Metrics by writing to the Prometheus
// DefaultRegisterer — the same registry that handler.MetricsHandler()
// (promhttp.Handler) exposes at /metrics.
type SOARPromAdapter struct {
	runsTotal       *prometheus.CounterVec
	stepsTotal      *prometheus.CounterVec
	retryTotal      *prometheus.CounterVec
	runDurationMS   *prometheus.HistogramVec
	stepDurationMS  *prometheus.HistogramVec
	activeRuns      prometheus.Gauge
	approvalPending prometheus.Gauge
}

var soarPromSingleton *SOARPromAdapter

// NewSOARPromAdapter returns a process-wide singleton adapter. Safe to call
// multiple times; instruments register exactly once with DefaultRegisterer.
func NewSOARPromAdapter() *SOARPromAdapter {
	if soarPromSingleton != nil {
		return soarPromSingleton
	}
	a := &SOARPromAdapter{
		runsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: soar.MetricRunsTotal,
			Help: "Total SOAR playbook runs by terminal status",
		}, []string{"status"}),
		stepsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: soar.MetricStepsTotal,
			Help: "Total step executions by type and status",
		}, []string{"step_type", "status"}),
		retryTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: soar.MetricRetryTotal,
			Help: "Step retries triggered by type",
		}, []string{"step_type"}),
		runDurationMS: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    soar.MetricRunDurationMS,
			Help:    "Run total duration in milliseconds",
			Buckets: []float64{50, 200, 500, 1000, 5000, 15000, 60000, 300000, 900000},
		}, []string{"status"}),
		stepDurationMS: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    soar.MetricStepDurationMS,
			Help:    "Step execution duration in milliseconds",
			Buckets: []float64{5, 25, 100, 500, 1000, 5000, 30000, 120000},
		}, []string{"step_type", "status"}),
		activeRuns: promauto.NewGauge(prometheus.GaugeOpts{
			Name: soar.MetricActiveRuns,
			Help: "Number of currently active (running) SOAR runs",
		}),
		approvalPending: promauto.NewGauge(prometheus.GaugeOpts{
			Name: soar.MetricApprovalPending,
			Help: "Number of pending approval gates",
		}),
	}
	soarPromSingleton = a
	return a
}

// CounterAdd implements soar.Metrics.
func (a *SOARPromAdapter) CounterAdd(name string, labels map[string]string, delta uint64) {
	if a == nil || delta == 0 {
		return
	}
	d := float64(delta)
	switch name {
	case soar.MetricRunsTotal:
		a.runsTotal.With(prometheus.Labels{"status": labels["status"]}).Add(d)
	case soar.MetricStepsTotal:
		a.stepsTotal.With(prometheus.Labels{
			"step_type": labels["step_type"],
			"status":    labels["status"],
		}).Add(d)
	case soar.MetricRetryTotal:
		a.retryTotal.With(prometheus.Labels{"step_type": labels["step_type"]}).Add(d)
	}
}

// GaugeSet implements soar.Metrics.
func (a *SOARPromAdapter) GaugeSet(name string, _ map[string]string, value float64) {
	if a == nil {
		return
	}
	switch name {
	case soar.MetricActiveRuns:
		a.activeRuns.Set(value)
	case soar.MetricApprovalPending:
		a.approvalPending.Set(value)
	}
}

// HistogramObserve implements soar.Metrics. SOAR emits milliseconds; histograms
// are in ms too (metric names end in _ms), so no unit conversion.
func (a *SOARPromAdapter) HistogramObserve(name string, labels map[string]string, value float64) {
	if a == nil {
		return
	}
	switch name {
	case soar.MetricRunDurationMS:
		a.runDurationMS.With(prometheus.Labels{"status": labels["status"]}).Observe(value)
	case soar.MetricStepDurationMS:
		a.stepDurationMS.With(prometheus.Labels{
			"step_type": labels["step_type"],
			"status":    labels["status"],
		}).Observe(value)
	}
}
