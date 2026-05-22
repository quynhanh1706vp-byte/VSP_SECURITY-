package soar

import "testing"

func TestNoopMetrics(t *testing.T) {
	var m Metrics = noopMetrics{}
	m.CounterAdd("x", nil, 1)
	m.GaugeSet("x", nil, 1)
	m.HistogramObserve("x", nil, 1)
}

func TestDescribeMetrics(t *testing.T) {
	descs := DescribeMetrics()
	for _, name := range []string{
		MetricRunsTotal, MetricStepDurationMS, MetricActiveRuns,
		MetricStepsTotal, MetricApprovalPending, MetricRetryTotal,
	} {
		if _, ok := descs[name]; !ok {
			t.Errorf("missing: %s", name)
		}
	}
}
