// Package handler — DORA (DevOps Research & Assessment) metrics.
//
// Returns the four canonical DORA metrics for the authenticated tenant:
//   - Deployment Frequency      (deploys/day, last 30d)
//   - Lead Time for Changes     (median hours, finding → merged fix)
//   - Mean Time to Restore      (median hours, incident detected → recovered)
//   - Change Failure Rate       (% of deploys that failed/rolled back)
//
// Data sources:
//   runs            — successful scan runs ≈ "deploys" (gate verdict gate=PASS)
//   autofix_pr      — merged PRs give finding → fix latency
//   ir_incidents    — incident lifecycle for MTTR
//
// Endpoint: GET /api/v1/dora?days=30  (default 30, max 365)
package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type DORA struct {
	DB *store.DB
}

func NewDORA(db *store.DB) *DORA { return &DORA{DB: db} }

type doraMetric struct {
	Value    float64 `json:"value"`
	Unit     string  `json:"unit"`
	Tier     string  `json:"tier"` // elite|high|medium|low — DORA classification
	Samples  int     `json:"samples"`
	Trend    float64 `json:"trend_pct"` // % change vs previous window
	Insight  string  `json:"insight,omitempty"`
}

func (h *DORA) Get(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}

	days := 30
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && v > 0 && v <= 365 {
		days = v
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	prevCutoff := time.Now().Add(-time.Duration(2*days) * 24 * time.Hour)

	deploy := h.deployFrequency(r, tenantID, cutoff, prevCutoff, days)
	lead := h.leadTime(r, tenantID, cutoff, prevCutoff)
	mttr := h.mttr(r, tenantID, cutoff, prevCutoff)
	cfr := h.changeFailureRate(r, tenantID, cutoff, prevCutoff)

	jsonOK(w, map[string]any{
		"window_days":         days,
		"deploy_frequency":    deploy,
		"lead_time":           lead,
		"mttr":                mttr,
		"change_failure_rate": cfr,
	})
}

// deployFrequency: passed scan runs per day. Tier thresholds per DORA 2023:
//   elite ≥ 1/day · high 1/day–1/week · medium 1/week–1/month · low < 1/month
func (h *DORA) deployFrequency(r *http.Request, tenant string, cur, prev time.Time, days int) doraMetric {
	var cnt, prevCnt int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM runs
		  WHERE tenant_id = $1 AND status = 'COMPLETED'
		    AND COALESCE(gate, '') IN ('', 'PASS')
		    AND finished_at >= $2`,
		tenant, cur).Scan(&cnt)
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM runs
		  WHERE tenant_id = $1 AND status = 'COMPLETED'
		    AND COALESCE(gate, '') IN ('', 'PASS')
		    AND finished_at >= $2 AND finished_at < $3`,
		tenant, prev, cur).Scan(&prevCnt)

	perDay := float64(cnt) / float64(days)
	tier := "low"
	insight := "Less than one deploy per month"
	switch {
	case perDay >= 1:
		tier = "elite"
		insight = "Multiple deploys per day"
	case perDay >= 1.0/7:
		tier = "high"
		insight = "1+ deploy per week"
	case perDay >= 1.0/30:
		tier = "medium"
		insight = "1+ deploy per month"
	}
	return doraMetric{
		Value:   round2(perDay),
		Unit:    "per_day",
		Tier:    tier,
		Samples: cnt,
		Trend:   pctDelta(cnt, prevCnt),
		Insight: insight,
	}
}

// leadTime: median hours between autofix_pr.created_at and merged_at
// for PRs merged in the window. (The PR's create time stands in for
// "code committed" — we don't have per-finding fix timestamps.)
func (h *DORA) leadTime(r *http.Request, tenant string, cur, prev time.Time) doraMetric {
	var cur50, prev50 *float64
	var samples, prevSamples int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT
		   PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (merged_at - created_at))/3600.0),
		   COUNT(*)
		 FROM autofix_pr
		 WHERE tenant_id = $1 AND pr_status = 'merged'
		   AND merged_at IS NOT NULL AND merged_at >= $2`,
		tenant, cur).Scan(&cur50, &samples)
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT
		   PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (merged_at - created_at))/3600.0),
		   COUNT(*)
		 FROM autofix_pr
		 WHERE tenant_id = $1 AND pr_status = 'merged'
		   AND merged_at IS NOT NULL
		   AND merged_at >= $2 AND merged_at < $3`,
		tenant, prev, cur).Scan(&prev50, &prevSamples)

	hrs := derefFloat(cur50)
	prevHrs := derefFloat(prev50)
	tier := "low"
	insight := "Lead time > 6 months"
	switch {
	case hrs > 0 && hrs < 24:
		tier = "elite"
		insight = "< 1 day from finding to fix merged"
	case hrs > 0 && hrs < 24*7:
		tier = "high"
		insight = "< 1 week from finding to fix merged"
	case hrs > 0 && hrs < 24*30:
		tier = "medium"
		insight = "< 1 month from finding to fix merged"
	case hrs == 0:
		tier = "n/a"
		insight = "No merged auto-fix PRs in window"
	}
	return doraMetric{
		Value:   round2(hrs),
		Unit:    "hours",
		Tier:    tier,
		Samples: samples,
		Trend:   pctDeltaF(hrs, prevHrs),
		Insight: insight,
	}
}

// mttr: median hours between detected_at and recovered_at for resolved incidents.
func (h *DORA) mttr(r *http.Request, tenant string, cur, prev time.Time) doraMetric {
	var cur50, prev50 *float64
	var samples int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT
		   PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (recovered_at - detected_at))/3600.0),
		   COUNT(*)
		 FROM ir_incidents
		 WHERE tenant_id = $1 AND recovered_at IS NOT NULL
		   AND recovered_at >= $2`,
		tenant, cur).Scan(&cur50, &samples)
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT
		   PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (recovered_at - detected_at))/3600.0)
		 FROM ir_incidents
		 WHERE tenant_id = $1 AND recovered_at IS NOT NULL
		   AND recovered_at >= $2 AND recovered_at < $3`,
		tenant, prev, cur).Scan(&prev50)

	hrs := derefFloat(cur50)
	prevHrs := derefFloat(prev50)
	tier := "low"
	insight := "MTTR > 1 week"
	switch {
	case samples == 0:
		tier = "n/a"
		insight = "No resolved incidents in window — system stable"
	case hrs < 1:
		tier = "elite"
		insight = "< 1 hour to restore"
	case hrs < 24:
		tier = "high"
		insight = "< 1 day to restore"
	case hrs < 24*7:
		tier = "medium"
		insight = "< 1 week to restore"
	}
	return doraMetric{
		Value:   round2(hrs),
		Unit:    "hours",
		Tier:    tier,
		Samples: samples,
		Trend:   pctDeltaF(hrs, prevHrs),
		Insight: insight,
	}
}

// changeFailureRate: % autofix PRs that ended in 'failed' or 'conflict' or
// were 'closed' without merge, vs total non-pending PRs in the window.
func (h *DORA) changeFailureRate(r *http.Request, tenant string, cur, prev time.Time) doraMetric {
	var failed, total, prevFailed, prevTotal int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT
		   COUNT(*) FILTER (WHERE pr_status IN ('failed','conflict','closed')),
		   COUNT(*)
		 FROM autofix_pr
		 WHERE tenant_id = $1
		   AND pr_status NOT IN ('pending','creating','created')
		   AND created_at >= $2`,
		tenant, cur).Scan(&failed, &total)
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT
		   COUNT(*) FILTER (WHERE pr_status IN ('failed','conflict','closed')),
		   COUNT(*)
		 FROM autofix_pr
		 WHERE tenant_id = $1
		   AND pr_status NOT IN ('pending','creating','created')
		   AND created_at >= $2 AND created_at < $3`,
		tenant, prev, cur).Scan(&prevFailed, &prevTotal)

	rate := 0.0
	if total > 0 {
		rate = float64(failed) / float64(total) * 100
	}
	prevRate := 0.0
	if prevTotal > 0 {
		prevRate = float64(prevFailed) / float64(prevTotal) * 100
	}
	tier := "low"
	insight := "More than 1 in 3 changes fail"
	switch {
	case total == 0:
		tier = "n/a"
		insight = "No completed change events in window"
	case rate <= 5:
		tier = "elite"
		insight = "≤ 5% of changes fail (industry elite)"
	case rate <= 10:
		tier = "high"
		insight = "≤ 10% of changes fail"
	case rate <= 15:
		tier = "medium"
		insight = "≤ 15% of changes fail"
	}
	return doraMetric{
		Value:   round2(rate),
		Unit:    "percent",
		Tier:    tier,
		Samples: total,
		Trend:   pctDeltaF(rate, prevRate),
		Insight: insight,
	}
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

func derefFloat(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

func pctDelta(cur, prev int) float64 {
	if prev == 0 {
		if cur > 0 {
			return 100
		}
		return 0
	}
	return round2(float64(cur-prev) / float64(prev) * 100)
}

func pctDeltaF(cur, prev float64) float64 {
	if prev == 0 {
		if cur > 0 {
			return 100
		}
		return 0
	}
	return round2((cur - prev) / prev * 100)
}
