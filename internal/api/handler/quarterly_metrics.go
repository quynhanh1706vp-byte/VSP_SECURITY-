// Package handler — quarterly continuous-improvement metrics.
//
// DSOMM Level 4 ("Optimised") expects evidence that the org is *getting
// better over time*, not just that today's numbers are good. This
// endpoint produces a per-quarter rollup of the headline KPIs so an
// auditor can see the trend at a glance:
//
//   - DORA metrics (deploy freq, lead time, MTTR, change failure rate)
//   - Posture score median across runs
//   - Audit-chain integrity events
//   - Disclosure SLA compliance (how often we hit ack/triage SLAs)
//   - Incident count + MTTR
//
// The endpoint computes the 4 most recent quarters on demand. We
// deliberately do not cache: the data set is small (4 rows), the
// queries are aggregate-only, and a quarter changes once per 90 days
// — no caching machinery earns its complexity.
//
// GET /api/v1/improvement/quarters
package handler

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Improvement struct {
	DB *store.DB
}

func NewImprovement(db *store.DB) *Improvement { return &Improvement{DB: db} }

type quarterRow struct {
	Quarter            string  `json:"quarter"` // "2026-Q2"
	Start              string  `json:"start"`
	End                string  `json:"end"`
	DeployFreq         float64 `json:"deploy_freq_per_day"`
	LeadTimeHrs        float64 `json:"lead_time_hours"`
	MTTRHrs            float64 `json:"mttr_hours"`
	ChangeFailRatePct  float64 `json:"change_fail_rate_pct"`
	IncidentCount      int     `json:"incident_count"`
	MedianPostureScore int     `json:"median_posture_score"`
	AuditChainBreaks   int     `json:"audit_chain_breaks"`
	DisclosureSLAHits  int     `json:"disclosure_sla_hits"`
	DisclosureCount    int     `json:"disclosure_count"`
}

func (h *Improvement) Quarters(w http.ResponseWriter, r *http.Request) {
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

	now := time.Now().UTC()
	quarters := lastNQuarters(now, 4)
	out := make([]quarterRow, 0, len(quarters))
	for _, q := range quarters {
		out = append(out, h.computeQuarter(r, tenantID, q))
	}
	// Hand back oldest-first so a chart can plot left-to-right.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	jsonOK(w, map[string]any{"quarters": out})
}

type qBounds struct {
	label      string
	start, end time.Time
}

func lastNQuarters(now time.Time, n int) []qBounds {
	out := make([]qBounds, 0, n)
	// Anchor on the start of the current quarter, then walk back.
	q := (int(now.Month())-1)/3 + 1
	year := now.Year()
	for i := 0; i < n; i++ {
		startMonth := time.Month((q-1)*3 + 1)
		start := time.Date(year, startMonth, 1, 0, 0, 0, 0, time.UTC)
		end := start.AddDate(0, 3, 0)
		out = append(out, qBounds{
			label: time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006") +
				"-Q" + string(rune('0'+q)), //#nosec G115 -- q bounded to [1,4]
			start: start,
			end:   end,
		})
		q--
		if q == 0 {
			q = 4
			year--
		}
	}
	return out
}

func (h *Improvement) computeQuarter(r *http.Request, tenant string, q qBounds) quarterRow {
	row := quarterRow{
		Quarter: q.label,
		Start:   q.start.Format("2006-01-02"),
		End:     q.end.Format("2006-01-02"),
	}
	days := q.end.Sub(q.start).Hours() / 24
	if days < 1 {
		days = 1
	}

	// Deploy freq — completed runs per day.
	var passed int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM runs
		  WHERE tenant_id = $1 AND status = 'COMPLETED'
		    AND finished_at >= $2 AND finished_at < $3`,
		tenant, q.start, q.end).Scan(&passed)
	row.DeployFreq = round2(float64(passed) / days)

	// Lead time + change failure rate from autofix_pr (re-uses dora.go logic
	// but bounded to the quarter).
	var leadHrs *float64
	var prTotal, prFailed int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT
		   PERCENTILE_CONT(0.5) WITHIN GROUP (
		     ORDER BY EXTRACT(EPOCH FROM (merged_at - created_at))/3600.0),
		   COUNT(*) FILTER (WHERE pr_status = 'merged'),
		   COUNT(*) FILTER (WHERE pr_status IN ('failed','conflict','closed'))
		 FROM autofix_pr
		 WHERE tenant_id = $1
		   AND created_at >= $2 AND created_at < $3
		   AND pr_status NOT IN ('pending','creating','created')`,
		tenant, q.start, q.end).Scan(&leadHrs, &prTotal, &prFailed)
	row.LeadTimeHrs = round2(derefFloat(leadHrs))
	if prTotal > 0 {
		row.ChangeFailRatePct = round2(float64(prFailed) / float64(prTotal) * 100)
	}

	// MTTR from ir_incidents.
	var mttr *float64
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (
		   ORDER BY EXTRACT(EPOCH FROM (recovered_at - detected_at))/3600.0)
		   FROM ir_incidents
		  WHERE tenant_id = $1 AND recovered_at IS NOT NULL
		    AND recovered_at >= $2 AND recovered_at < $3`,
		tenant, q.start, q.end).Scan(&mttr)
	row.MTTRHrs = round2(derefFloat(mttr))

	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM ir_incidents
		  WHERE tenant_id = $1 AND detected_at >= $2 AND detected_at < $3`,
		tenant, q.start, q.end).Scan(&row.IncidentCount)

	// Median posture score — only available where runs.summary holds the
	// score JSON path; older runs have it via the gate decision row.
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COALESCE(
		   PERCENTILE_CONT(0.5) WITHIN GROUP (
		     ORDER BY (summary->>'score')::int
		   )::int, 0)
		   FROM runs
		  WHERE tenant_id = $1 AND status = 'COMPLETED'
		    AND finished_at >= $2 AND finished_at < $3
		    AND summary ? 'score'`,
		tenant, q.start, q.end).Scan(&row.MedianPostureScore)

	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM audit_log
		  WHERE tenant_id = $1 AND action = 'CHAIN_BROKEN'
		    AND created_at >= $2 AND created_at < $3`,
		tenant, q.start, q.end).Scan(&row.AuditChainBreaks)

	// Disclosure SLA compliance — across all reports submitted in the
	// quarter, how many were ack'd before ack_due_at?
	var hits, totalDisc int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT
		   COUNT(*) FILTER (WHERE acknowledged_at IS NOT NULL
		                    AND acknowledged_at <= ack_due_at),
		   COUNT(*)
		   FROM security_disclosures
		  WHERE submitted_at >= $1 AND submitted_at < $2`,
		q.start, q.end).Scan(&hits, &totalDisc)
	row.DisclosureSLAHits = hits
	row.DisclosureCount = totalDisc

	return row
}
