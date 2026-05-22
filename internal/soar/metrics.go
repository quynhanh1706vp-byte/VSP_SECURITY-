package soar

// Metrics — minimal interface engine uses for telemetry.
// Implemented by *telemetry.Registry in production, no-op in tests.
type Metrics interface {
	// CounterAdd increments a named counter by delta with optional labels.
	CounterAdd(name string, labels map[string]string, delta uint64)
	// GaugeSet sets a gauge to value with optional labels.
	GaugeSet(name string, labels map[string]string, value float64)
	// HistogramObserve records a duration sample.
	HistogramObserve(name string, labels map[string]string, value float64)
}

// noopMetrics — default for tests. All methods are no-ops.
type noopMetrics struct{}

func (noopMetrics) CounterAdd(string, map[string]string, uint64)        {}
func (noopMetrics) GaugeSet(string, map[string]string, float64)         {}
func (noopMetrics) HistogramObserve(string, map[string]string, float64) {}

// Metric names — exported so handlers/tests can reference.
const (
	MetricRunsTotal       = "soar_runs_total"       // counter, label: status
	MetricStepDurationMS  = "soar_step_duration_ms" // histogram, labels: step_type, status
	MetricRunDurationMS   = "soar_run_duration_ms"  // histogram, label: status
	MetricActiveRuns      = "soar_active_runs"      // gauge
	MetricStepsTotal      = "soar_steps_total"      // counter, labels: step_type, status
	MetricApprovalPending = "soar_approval_pending" // gauge
	MetricRetryTotal      = "soar_step_retry_total" // counter, label: step_type
)

// DescribeMetrics returns metric metadata for caller to register with telemetry.
// Format: name → (description, type)
func DescribeMetrics() map[string][2]string {
	return map[string][2]string{
		MetricRunsTotal:       {"Total SOAR playbook runs by terminal status", "counter"},
		MetricStepDurationMS:  {"Step execution duration in milliseconds", "histogram"},
		MetricRunDurationMS:   {"Run total duration in milliseconds", "histogram"},
		MetricActiveRuns:      {"Number of currently active (running) SOAR runs", "gauge"},
		MetricStepsTotal:      {"Total step executions by type and status", "counter"},
		MetricApprovalPending: {"Number of pending approval gates", "gauge"},
		MetricRetryTotal:      {"Step retries triggered", "counter"},
	}
}
