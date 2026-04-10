package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/siem"
	"github.com/vsp/platform/internal/store"
)

type UEBA struct{ DB *store.DB }

// GET /api/v1/ueba/anomalies
func (h *UEBA) ListAnomalies(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT id, title, severity, status,
		       source_refs, created_at
		FROM   incidents
		WHERE  tenant_id=$1
		  AND  source_refs::text LIKE '%score%'
		   OR  source_refs::text LIKE '%anomaly%'
		   OR  source_refs::text LIKE '%ueba%'
		ORDER  BY created_at DESC LIMIT 50`, claims.TenantID)
	if err != nil {
		jsonOK(w, map[string]any{"anomalies": []any{}, "total": 0})
		return
	}
	defer rows.Close()
	type Anomaly struct {
		ID         string          `json:"id"`
		Title      string          `json:"title"`
		Severity   string          `json:"severity"`
		Status     string          `json:"status"`
		SourceRefs json.RawMessage `json:"source_refs"`
		DetectedAt time.Time       `json:"detected_at"`
	}
	var out []Anomaly
	for rows.Next() {
		var a Anomaly
		rows.Scan(&a.ID, &a.Title, &a.Severity, &a.Status, &a.SourceRefs, &a.DetectedAt) //nolint:errcheck
		out = append(out, a)
	}
	if out == nil {
		out = []Anomaly{}
	}
	jsonOK(w, map[string]any{"anomalies": out, "total": len(out)})
}

// POST /api/v1/ueba/analyze  — trigger on-demand analysis
func (h *UEBA) Analyze(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	engine := siem.NewUEBAEngine(h.DB, claims.TenantID)
	anomalies, err := engine.Analyze(r.Context())
	if err != nil {
		jsonError(w, "analysis failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Persist significant anomalies as incidents
	saved := 0
	for _, a := range anomalies {
		if a.Score < 30 {
			continue
		}
		srcJSON, _ := json.Marshal(map[string]any{
			"type": a.Type, "score": a.Score,
			"entity": a.Entity, "baseline": a.Baseline,
			"current": a.Current, "deviation_pct": a.Deviation,
		})
		title := a.Message
		if len(title) > 200 {
			title = title[:200]
		}
		h.DB.Pool().Exec(r.Context(), `
			INSERT INTO incidents
				(tenant_id, title, severity, status, source_refs)
			VALUES ($1,$2,$3,'open',$4)`,
			claims.TenantID, title, a.Severity, srcJSON) //nolint:errcheck
		saved++
	}
	jsonOK(w, map[string]any{
		"anomalies":   anomalies,
		"total":       len(anomalies),
		"saved":       saved,
		"analyzed_at": time.Now(),
	})
}

// GET /api/v1/ueba/baseline
func (h *UEBA) Baseline(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	type Stats struct {
		AvgScore       float64 `json:"avg_score"`
		StdScore       float64 `json:"std_score"`
		AvgFindings    float64 `json:"avg_findings"`
		GatePassRate   float64 `json:"gate_pass_rate"`
		AvgScansPerDay float64 `json:"avg_scans_per_day"`
		Period         string  `json:"period"`
	}
	var s Stats
	h.DB.Pool().QueryRow(r.Context(), `
		SELECT
			COALESCE(AVG(COALESCE((summary->>'SCORE')::float,0)),0),
			COALESCE(STDDEV(COALESCE((summary->>'SCORE')::float,0)),0),
			COALESCE(AVG(COALESCE(total_findings,0)),0),
			COALESCE(COUNT(CASE WHEN gate='PASS' THEN 1 END)::float / NULLIF(COUNT(*),0),0),
			COALESCE(COUNT(*)::float / 30, 0)
		FROM runs
		WHERE tenant_id=$1
		  AND created_at > NOW() - INTERVAL '30 days'
		  AND status='DONE'`, claims.TenantID,
	).Scan(&s.AvgScore, &s.StdScore, &s.AvgFindings, &s.GatePassRate, &s.AvgScansPerDay) //nolint:errcheck
	s.Period = "30d"
	jsonOK(w, s)
}

// GET /api/v1/ueba/timeline  — score + findings over time
func (h *UEBA) Timeline(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT
			DATE_TRUNC('day', created_at) as day,
			AVG(COALESCE((summary->>'SCORE')::float,0)) as avg_score,
			SUM(COALESCE(total_findings,0)) as total_findings,
			COUNT(*) as scan_count,
			COUNT(CASE WHEN gate='PASS' THEN 1 END) as pass_count
		FROM runs
		WHERE tenant_id=$1
		  AND created_at > NOW() - INTERVAL '30 days'
		  AND status='DONE'
		GROUP BY day ORDER BY day ASC`, claims.TenantID)
	if err != nil {
		jsonOK(w, map[string]any{"timeline": []any{}})
		return
	}
	defer rows.Close()
	type Point struct {
		Day      time.Time `json:"day"`
		Score    float64   `json:"score"`
		Findings int       `json:"findings"`
		Scans    int       `json:"scans"`
		Passes   int       `json:"passes"`
	}
	var pts []Point
	for rows.Next() {
		var p Point
		rows.Scan(&p.Day, &p.Score, &p.Findings, &p.Scans, &p.Passes) //nolint:errcheck
		pts = append(pts, p)
	}
	if pts == nil {
		pts = []Point{}
	}
	jsonOK(w, map[string]any{"timeline": pts, "total": len(pts)})
}
