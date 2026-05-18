package handlers

import (
	"database/sql"
	"net/http"
	"sync"
	"time"
)

// MetricsTotals are absolute counts of findings per status.
// Maps to CMMC AU-7 (Audit Reduction & Report Generation).
type MetricsTotals struct {
	Open          int `json:"findings_open"`
	Applied       int `json:"findings_applied"`
	Verified      int `json:"findings_verified"`
	Failed        int `json:"findings_failed"`
	Accepted      int `json:"findings_accepted"`
	FalsePositive int `json:"findings_false_pos"`
}

// MetricsRates are derived ratios useful for SI-2 (Flaw Remediation) reporting.
type MetricsRates struct {
	VerificationRate    float64 `json:"verification_rate"`     // verified / (verified + applied)
	FirstAttemptSuccess float64 `json:"first_attempt_success"` // verified / (verified + failed)
	AutoRemediationRate float64 `json:"auto_remediation_rate"` // applied / (applied + manual_resolved)
}

// MetricsMTTR is mean time to remediate per severity, in hours.
// Maps to RA-5 (Vulnerability Scanning) effectiveness measurement.
type MetricsMTTR struct {
	CriticalHours float64 `json:"critical_hours"`
	HighHours     float64 `json:"high_hours"`
	MediumHours   float64 `json:"medium_hours"`
	LowHours      float64 `json:"low_hours"`
	OverallHours  float64 `json:"overall_hours"`
}

// MetricsResponse is the full payload returned to the Autofix metrics card.
type MetricsResponse struct {
	PeriodDays  int           `json:"period_days"`
	TenantID    string        `json:"tenant_id"`
	GeneratedAt time.Time     `json:"generated_at"`
	Totals      MetricsTotals `json:"totals"`
	Rates       MetricsRates  `json:"rates"`
	MTTR        MetricsMTTR   `json:"mttr"`
	TopRules    []RuleStat    `json:"top_rules_remediated"`
}

type RuleStat struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

// In-memory cache to avoid hammering DB. 5-minute TTL.
type cachedMetrics struct {
	data    MetricsResponse
	expires time.Time
}

var (
	metricsCache = map[string]cachedMetrics{}
	metricsMu    sync.RWMutex
)

// AutofixMetricsHandler returns GET /api/v1/autofix/metrics?period=30d
// Cached 5 minutes per (period, tenant) tuple.
func AutofixMetricsHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		period := r.URL.Query().Get("period")
		if period == "" {
			period = "30d"
		}
		tenant := r.URL.Query().Get("tenant_id")
		if tenant == "" {
			tenant = "default"
		}

		cacheKey := period + ":" + tenant
		metricsMu.RLock()
		c, ok := metricsCache[cacheKey]
		metricsMu.RUnlock()
		if ok && time.Now().Before(c.expires) {
			writeJSON(w, c.data)
			return
		}

		days := 30
		switch period {
		case "7d":
			days = 7
		case "90d":
			days = 90
		case "all":
			days = 36500
		}

		resp := MetricsResponse{
			PeriodDays:  days,
			TenantID:    tenant,
			GeneratedAt: time.Now().UTC(),
		}

		// Query 1: totals by status (graceful fallback to 0 on error)
		_ = db.QueryRowContext(r.Context(), `
			SELECT
				COUNT(*) FILTER (WHERE status = 'open'),
				COUNT(*) FILTER (WHERE status = 'fix_applied'),
				COUNT(*) FILTER (WHERE status = 'verified'),
				COUNT(*) FILTER (WHERE status = 'fix_failed'),
				COUNT(*) FILTER (WHERE status = 'accepted'),
				COUNT(*) FILTER (WHERE status = 'false_positive')
			FROM remediation
			WHERE created_at > NOW() - ($1 || ' days')::INTERVAL
		`, days).Scan(
			&resp.Totals.Open,
			&resp.Totals.Applied,
			&resp.Totals.Verified,
			&resp.Totals.Failed,
			&resp.Totals.Accepted,
			&resp.Totals.FalsePositive,
		)

		// Derive rates safely (avoid divide-by-zero)
		if v := resp.Totals.Verified + resp.Totals.Applied; v > 0 {
			resp.Rates.VerificationRate = float64(resp.Totals.Verified) / float64(v)
		}
		if v := resp.Totals.Verified + resp.Totals.Failed; v > 0 {
			resp.Rates.FirstAttemptSuccess = float64(resp.Totals.Verified) / float64(v)
		}
		manualResolved := resp.Totals.Accepted + resp.Totals.FalsePositive
		if v := resp.Totals.Applied + manualResolved; v > 0 {
			resp.Rates.AutoRemediationRate = float64(resp.Totals.Applied) / float64(v)
		}

		// Query 2: top rules (best effort — rule_id may be in findings table)
		rows, _ := db.QueryContext(r.Context(), `
			SELECT f.rule_id, COUNT(*)
			FROM findings f
			JOIN remediation r ON r.finding_id = f.id
			WHERE r.status = 'verified'
			  AND r.updated_at > NOW() - ($1 || ' days')::INTERVAL
			GROUP BY f.rule_id
			ORDER BY 2 DESC
			LIMIT 10
		`, days)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var s RuleStat
				if err := rows.Scan(&s.RuleID, &s.Count); err == nil {
					resp.TopRules = append(resp.TopRules, s)
				}
			}
		}

		// Cache for 5 minutes
		metricsMu.Lock()
		metricsCache[cacheKey] = cachedMetrics{
			data:    resp,
			expires: time.Now().Add(5 * time.Minute),
		}
		metricsMu.Unlock()

		writeJSON(w, resp)
	}
}
