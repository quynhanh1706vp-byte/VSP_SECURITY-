package handler

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type SLA struct{ DB *store.DB }

type slaEntry struct {
	Severity    string        `json:"severity"`
	SLADays     int           `json:"sla_days"`
	OpenCount   int           `json:"open_count"`
	BreachCount int           `json:"breach_count"`
	AvgAgeDays  float64       `json:"avg_age_days"`
	Status      string        `json:"status"` // green/yellow/red
}

// GET /api/v1/vsp/sla_tracker
func (h *SLA) Tracker(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	findings, _, err := h.DB.ListFindings(r.Context(), claims.TenantID, store.FindingFilter{Limit: 5000})
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }

	sla := map[string]int{"CRITICAL": 3, "HIGH": 14, "MEDIUM": 30, "LOW": 90}
	type bucket struct { open, breach int; totalAge float64 }
	buckets := map[string]*bucket{}
	for k := range sla { buckets[k] = &bucket{} }

	now := time.Now()
	for _, f := range findings {
		b, ok := buckets[f.Severity]
		if !ok { continue }
		b.open++
		age := now.Sub(f.CreatedAt).Hours() / 24
		b.totalAge += age
		if age > float64(sla[f.Severity]) { b.breach++ }
	}

	entries := make([]slaEntry, 0, 4)
	for _, sev := range []string{"CRITICAL","HIGH","MEDIUM","LOW"} {
		b := buckets[sev]
		avg := 0.0
		if b.open > 0 { avg = b.totalAge / float64(b.open) }
		status := "green"
		if b.breach > 0 { status = "red" } else if avg > float64(sla[sev])*0.8 { status = "yellow" }
		entries = append(entries, slaEntry{
			Severity:    sev,
			SLADays:     sla[sev],
			OpenCount:   b.open,
			BreachCount: b.breach,
			AvgAgeDays:  avg,
			Status:      status,
		})
	}
	jsonOK(w, map[string]any{"sla": entries, "as_of": now})
}

// GET /api/v1/vsp/metrics_slos
func (h *SLA) MetricsSLOs(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	runs, err := h.DB.ListRuns(r.Context(), claims.TenantID, 100, 0)
	if err != nil { jsonError(w, "db error", http.StatusInternalServerError); return }

	var totalDur, count float64
	passCount, failCount := 0, 0
	for _, run := range runs {
		if run.Status != "DONE" { continue }
		if run.FinishedAt != nil && run.StartedAt != nil {
			dur := run.FinishedAt.Sub(*run.StartedAt).Seconds()
			totalDur += dur
			count++
		}
		if run.Gate == "PASS" { passCount++ } else if run.Gate == "FAIL" { failCount++ }
	}
	avgDur := 0.0
	if count > 0 { avgDur = totalDur / count }
	total := passCount + failCount
	passRate := 0.0
	if total > 0 { passRate = float64(passCount) / float64(total) * 100 }

	jsonOK(w, map[string]any{
		"avg_scan_duration_sec": avgDur,
		"pass_rate_pct":         passRate,
		"total_scans":           len(runs),
		"pass_count":            passCount,
		"fail_count":            failCount,
		"slo_scan_time_target":  300,
		"slo_scan_time_met":     avgDur < 300,
		"slo_pass_rate_target":  80.0,
		"slo_pass_rate_met":     passRate >= 80.0,
	})
}
