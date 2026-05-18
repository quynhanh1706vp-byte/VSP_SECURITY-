package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// Analytics serves the Analytics panel's aggregation endpoint. The free-tier
// dashboard reads /api/v1/vsp/runs/index and computes charts client-side; this
// PRO endpoint moves that aggregation to Postgres so larger tenants don't ship
// thousands of rows over the wire just to render a sparkline.
type Analytics struct {
	DB *store.DB
}

func NewAnalytics(db *store.DB) *Analytics { return &Analytics{DB: db} }

// Summary — GET /api/v1/analytics/summary?days=N
//
// Returns per-day aggregates for the requested window. Fields:
//   - total_runs / failed_runs
//   - findings_by_severity (critical / high / medium / low)
//   - mttr_hours (mean time-to-remediate within the window)
//   - top_tools (tool → finding count, top 5)
//
// All counts are tenant-scoped. PRO gating + retention cap enforced upstream.
func (h *Analytics) Summary(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	days := queryInt(r, "days", 30)
	if days < 1 || days > 730 {
		days = 30
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	// Resolve tenant slug → UUID (mint script tokens carry slug, real
	// session JWTs carry UUID — handle both like Threat Hunt does).
	tenantID := claims.TenantID
	if len(tenantID) != 36 {
		var id string
		_ = h.DB.Pool().QueryRow(r.Context(),
			`SELECT id::text FROM tenants WHERE slug = $1 LIMIT 1`, tenantID).Scan(&id)
		if id == "" {
			jsonError(w, "tenant not found", http.StatusForbidden)
			return
		}
		tenantID = id
	}

	pool := h.DB.Pool()
	out := map[string]any{
		"window_days": days,
		"since":       cutoff.UTC().Format(time.RFC3339),
	}

	// Total + failed runs over the window. Schema: runs.status = QUEUED |
	// RUNNING | DONE | FAILED; runs.gate = PASS | FAIL (set when status=DONE).
	// Treat anything except PASS as a failed gate.
	var totalRuns, failedRuns int64
	_ = pool.QueryRow(r.Context(),
		`SELECT COUNT(*),
		        COUNT(*) FILTER (WHERE COALESCE(gate,'') NOT IN ('PASS','PASSED'))
		   FROM runs
		  WHERE tenant_id = $1 AND created_at >= $2`,
		tenantID, cutoff).Scan(&totalRuns, &failedRuns)
	out["total_runs"] = totalRuns
	out["failed_runs"] = failedRuns
	if totalRuns > 0 {
		out["fail_rate_pct"] = float64(failedRuns) * 100.0 / float64(totalRuns)
	} else {
		out["fail_rate_pct"] = 0.0
	}

	// Findings by severity.
	rows, err := pool.Query(r.Context(),
		`SELECT severity, COUNT(*)
		   FROM findings
		  WHERE tenant_id = $1 AND created_at >= $2
		  GROUP BY severity`,
		tenantID, cutoff)
	bySev := map[string]int64{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	if err == nil {
		for rows.Next() {
			var sev string
			var n int64
			if rows.Scan(&sev, &n) == nil {
				bySev[sev] = n
			}
		}
		rows.Close()
	}
	out["findings_by_severity"] = bySev

	// Top 5 tools by finding count. Useful for the "scanner mix" pie chart.
	type tool struct {
		Tool  string `json:"tool"`
		Count int64  `json:"count"`
	}
	var tops []tool
	rows2, err := pool.Query(r.Context(),
		`SELECT tool, COUNT(*) AS c
		   FROM findings
		  WHERE tenant_id = $1 AND created_at >= $2
		  GROUP BY tool
		  ORDER BY c DESC
		  LIMIT 5`,
		tenantID, cutoff)
	if err == nil {
		for rows2.Next() {
			var t tool
			if rows2.Scan(&t.Tool, &t.Count) == nil {
				tops = append(tops, t)
			}
		}
		rows2.Close()
	}
	if tops == nil {
		tops = []tool{}
	}
	out["top_tools"] = tops

	// MTTR — average hours between finding creation and remediation closure.
	// remediations.resolved_at is set when status transitions to "resolved".
	var mttrHours float64
	_ = pool.QueryRow(r.Context(),
		`SELECT COALESCE(
		   AVG(EXTRACT(EPOCH FROM (rem.resolved_at - f.created_at)) / 3600.0),
		   0)
		   FROM findings f
		   JOIN remediations rem ON rem.finding_id = f.id
		  WHERE f.tenant_id = $1
		    AND f.created_at >= $2
		    AND rem.resolved_at IS NOT NULL`,
		tenantID, cutoff).Scan(&mttrHours)
	out["mttr_hours"] = mttrHours

	jsonOK(w, out)
}

// ─── GET /api/v1/analytics/trends?days=N ───────────────────────────────────
// Per-day breakdown — sparkline/chart data cho frontend
func (h *Analytics) Trends(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	days := queryInt(r, "days", 30)
	if days < 1 || days > 365 {
		days = 30
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	tenantID := claims.TenantID
	if len(tenantID) != 36 {
		var id string
		_ = h.DB.Pool().QueryRow(r.Context(),
			`SELECT id::text FROM tenants WHERE slug=$1 LIMIT 1`, tenantID).Scan(&id)
		if id != "" {
			tenantID = id
		}
	}

	// Per-day run counts
	type dayRun struct {
		Day    string `json:"day"`
		Total  int64  `json:"total"`
		Failed int64  `json:"failed"`
	}
	var runs []dayRun
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT DATE(created_at)::text,
		        COUNT(*),
		        COUNT(*) FILTER (WHERE COALESCE(gate,'') NOT IN ('PASS','PASSED'))
		 FROM runs
		 WHERE tenant_id=$1 AND created_at>=$2
		 GROUP BY DATE(created_at)
		 ORDER BY DATE(created_at) ASC`,
		tenantID, cutoff)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d dayRun
			if rows.Scan(&d.Day, &d.Total, &d.Failed) == nil {
				runs = append(runs, d)
			}
		}
	}
	if runs == nil {
		runs = []dayRun{}
	}

	// Per-day finding counts by severity
	type dayFinding struct {
		Day      string `json:"day"`
		Critical int64  `json:"critical"`
		High     int64  `json:"high"`
		Medium   int64  `json:"medium"`
		Low      int64  `json:"low"`
	}
	var findings []dayFinding
	rows2, err := h.DB.Pool().Query(r.Context(),
		`SELECT DATE(created_at)::text,
		        COUNT(*) FILTER (WHERE severity='CRITICAL'),
		        COUNT(*) FILTER (WHERE severity='HIGH'),
		        COUNT(*) FILTER (WHERE severity='MEDIUM'),
		        COUNT(*) FILTER (WHERE severity='LOW')
		 FROM findings
		 WHERE tenant_id=$1 AND created_at>=$2
		 GROUP BY DATE(created_at)
		 ORDER BY DATE(created_at) ASC`,
		tenantID, cutoff)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var d dayFinding
			if rows2.Scan(&d.Day, &d.Critical, &d.High, &d.Medium, &d.Low) == nil {
				findings = append(findings, d)
			}
		}
	}
	if findings == nil {
		findings = []dayFinding{}
	}

	jsonOK(w, map[string]any{
		"window_days": days,
		"since":       cutoff.UTC().Format(time.RFC3339),
		"runs":        runs,
		"findings":    findings,
	})
}

// ─── GET /api/v1/analytics/export?days=N&format=csv|json ───────────────────
// Export analytics summary as CSV or JSON
func (h *Analytics) Export(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	days := queryInt(r, "days", 30)
	if days < 1 || days > 365 {
		days = 30
	}
	format := r.URL.Query().Get("format")
	if format != "csv" {
		format = "json"
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	tenantID := claims.TenantID
	if len(tenantID) != 36 {
		var id string
		_ = h.DB.Pool().QueryRow(r.Context(),
			`SELECT id::text FROM tenants WHERE slug=$1 LIMIT 1`, tenantID).Scan(&id)
		if id != "" {
			tenantID = id
		}
	}

	type exportRow struct {
		Day      string `json:"day"`
		Runs     int64  `json:"runs"`
		Failed   int64  `json:"failed"`
		Critical int64  `json:"critical"`
		High     int64  `json:"high"`
		Medium   int64  `json:"medium"`
		Low      int64  `json:"low"`
	}

	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT
		   DATE(r.created_at)::text,
		   COUNT(DISTINCT r.id),
		   COUNT(DISTINCT r.id) FILTER (WHERE COALESCE(r.gate,'') NOT IN ('PASS','PASSED')),
		   COUNT(f.id) FILTER (WHERE f.severity='CRITICAL'),
		   COUNT(f.id) FILTER (WHERE f.severity='HIGH'),
		   COUNT(f.id) FILTER (WHERE f.severity='MEDIUM'),
		   COUNT(f.id) FILTER (WHERE f.severity='LOW')
		 FROM runs r
		 LEFT JOIN findings f ON f.tenant_id=r.tenant_id
		   AND DATE(f.created_at)=DATE(r.created_at)
		 WHERE r.tenant_id=$1 AND r.created_at>=$2
		 GROUP BY DATE(r.created_at)
		 ORDER BY DATE(r.created_at) ASC`,
		tenantID, cutoff)

	var data []exportRow
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var row exportRow
			if rows.Scan(&row.Day, &row.Runs, &row.Failed,
				&row.Critical, &row.High, &row.Medium, &row.Low) == nil {
				data = append(data, row)
			}
		}
	}
	if data == nil {
		data = []exportRow{}
	}

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition",
			"attachment; filename=analytics-export.csv")
		fmt.Fprintln(w, "day,runs,failed,critical,high,medium,low")
		for _, row := range data {
			fmt.Fprintf(w, "%s,%d,%d,%d,%d,%d,%d\n",
				row.Day, row.Runs, row.Failed,
				row.Critical, row.High, row.Medium, row.Low)
		}
		return
	}

	jsonOK(w, map[string]any{
		"window_days": days,
		"format":      format,
		"rows":        data,
		"exported_at": time.Now().UTC().Format(time.RFC3339),
	})
}
