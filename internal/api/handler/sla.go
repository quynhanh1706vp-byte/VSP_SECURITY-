package handler

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type SLA struct{ DB *store.DB }

type slaEntry struct {
	Severity    string  `json:"severity"`
	SLADays     int     `json:"sla_days"`
	OpenCount   int     `json:"open_count"`
	BreachCount int     `json:"breach_count"`
	AvgAgeDays  float64 `json:"avg_age_days"`
	Status      string  `json:"status"` // green/yellow/red
}

// GET /api/v1/vsp/sla_tracker
func (h *SLA) Tracker(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	latestRun, _ := h.DB.GetLatestRun(r.Context(), claims.TenantID)
	runID := ""
	if latestRun != nil && latestRun.Status == "DONE" {
		runID = latestRun.ID
	}
	findings, _, err := h.DB.ListFindings(r.Context(), claims.TenantID, store.FindingFilter{RunID: runID, Limit: 5000})
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	sla := map[string]int{"CRITICAL": 3, "HIGH": 14, "MEDIUM": 30, "LOW": 90}
	type bucket struct {
		open, breach int
		totalAge     float64
	}
	buckets := map[string]*bucket{}
	for k := range sla {
		buckets[k] = &bucket{}
	}

	now := time.Now()
	for _, f := range findings {
		b, ok := buckets[f.Severity]
		if !ok {
			continue
		}
		b.open++
		age := now.Sub(f.CreatedAt).Hours() / 24
		b.totalAge += age
		if age > float64(sla[f.Severity]) {
			b.breach++
		}
	}

	entries := make([]slaEntry, 0, 4)
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		b := buckets[sev]
		avg := 0.0
		if b.open > 0 {
			avg = b.totalAge / float64(b.open)
		}
		status := "green"
		if b.breach > 0 {
			status = "red"
		} else if avg > float64(sla[sev])*0.8 {
			status = "yellow"
		}
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
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	var totalDur, count float64
	passCount, failCount := 0, 0
	for _, run := range runs {
		if run.Status != "DONE" {
			continue
		}
		if run.FinishedAt != nil && run.StartedAt != nil {
			dur := run.FinishedAt.Sub(*run.StartedAt).Seconds()
			totalDur += dur
			count++
		}
		if run.Gate == "PASS" {
			passCount++
		} else if run.Gate == "FAIL" {
			failCount++
		}
	}
	avgDur := 0.0
	if count > 0 {
		avgDur = totalDur / count
	}
	total := passCount + failCount
	passRate := 0.0
	if total > 0 {
		passRate = float64(passCount) / float64(total) * 100
	}

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

// ─── GET /api/v1/vsp/sla_config ────────────────────────────────────────────
type slaConfig struct {
	CriticalDays int       `json:"critical_days"`
	HighDays     int       `json:"high_days"`
	MediumDays   int       `json:"medium_days"`
	LowDays      int       `json:"low_days"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (h *SLA) Config(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var c slaConfig
	err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO sla_config(tenant_id) VALUES($1)
		 ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id
		 RETURNING critical_days, high_days, medium_days, low_days, updated_at`,
		claims.TenantID).Scan(&c.CriticalDays, &c.HighDays, &c.MediumDays, &c.LowDays, &c.UpdatedAt)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, c)
}

// ─── PUT /api/v1/vsp/sla_config ────────────────────────────────────────────
func (h *SLA) ConfigPut(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		CriticalDays int `json:"critical_days"`
		HighDays     int `json:"high_days"`
		MediumDays   int `json:"medium_days"`
		LowDays      int `json:"low_days"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	// Validate: phải > 0
	if req.CriticalDays <= 0 || req.HighDays <= 0 || req.MediumDays <= 0 || req.LowDays <= 0 {
		jsonError(w, "all sla days must be > 0", http.StatusBadRequest)
		return
	}
	// Validate: thứ tự hợp lý critical < high < medium < low
	if req.CriticalDays >= req.HighDays || req.HighDays >= req.MediumDays || req.MediumDays >= req.LowDays {
		jsonError(w, "sla days must be in order: critical < high < medium < low", http.StatusBadRequest)
		return
	}
	var updatedAt time.Time
	err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO sla_config(tenant_id, critical_days, high_days, medium_days, low_days, updated_at)
		 VALUES($1,$2,$3,$4,$5,NOW())
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   critical_days=$2, high_days=$3, medium_days=$4, low_days=$5, updated_at=NOW()
		 RETURNING updated_at`,
		claims.TenantID, req.CriticalDays, req.HighDays, req.MediumDays, req.LowDays).
		Scan(&updatedAt)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"critical_days": req.CriticalDays,
		"high_days":     req.HighDays,
		"medium_days":   req.MediumDays,
		"low_days":      req.LowDays,
		"updated_at":    updatedAt,
	})
}

// ─── GET /api/v1/vsp/sla_breaches ──────────────────────────────────────────
// Trả danh sách findings đang breach SLA (để drill-down từ SLA tab)
type slaBreachEntry struct {
	FindingID string  `json:"finding_id"`
	Severity  string  `json:"severity"`
	RuleID    string  `json:"rule_id"`
	Tool      string  `json:"tool"`
	Path      string  `json:"path"`
	Message   string  `json:"message"`
	AgeDays   float64 `json:"age_days"`
	SLADays   int     `json:"sla_days"`
	OverDays  float64 `json:"over_days"`
}

func (h *SLA) Breaches(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	ctx := r.Context()

	// Load SLA config (fallback defaults)
	var cfg slaConfig
	cfg.CriticalDays, cfg.HighDays, cfg.MediumDays, cfg.LowDays = 3, 14, 30, 90
	_ = h.DB.Pool().QueryRow(ctx,
		`SELECT critical_days, high_days, medium_days, low_days FROM sla_config WHERE tenant_id=$1`,
		claims.TenantID).Scan(&cfg.CriticalDays, &cfg.HighDays, &cfg.MediumDays, &cfg.LowDays)

	slaMap := map[string]int{
		"CRITICAL": cfg.CriticalDays,
		"HIGH":     cfg.HighDays,
		"MEDIUM":   cfg.MediumDays,
		"LOW":      cfg.LowDays,
	}

	latestRun, _ := h.DB.GetLatestRun(ctx, claims.TenantID)
	runID := ""
	if latestRun != nil && latestRun.Status == "DONE" {
		runID = latestRun.ID
	}

	findings, _, err := h.DB.ListFindings(ctx, claims.TenantID,
		store.FindingFilter{RunID: runID, Limit: 5000})
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	var breaches []slaBreachEntry
	for _, f := range findings {
		slaDays, ok := slaMap[f.Severity]
		if !ok {
			continue
		}
		age := now.Sub(f.CreatedAt).Hours() / 24
		if age > float64(slaDays) {
			breaches = append(breaches, slaBreachEntry{
				FindingID: f.ID,
				Severity:  f.Severity,
				RuleID:    f.RuleID,
				Tool:      f.Tool,
				Path:      f.Path,
				Message:   f.Message,
				AgeDays:   age,
				SLADays:   slaDays,
				OverDays:  age - float64(slaDays),
			})
		}
	}
	if breaches == nil {
		breaches = []slaBreachEntry{}
	}

	severity := r.URL.Query().Get("severity")
	if severity != "" {
		var filtered []slaBreachEntry
		for _, b := range breaches {
			if b.Severity == severity {
				filtered = append(filtered, b)
			}
		}
		breaches = filtered
	}

	jsonOK(w, map[string]any{
		"breaches": breaches,
		"total":    len(breaches),
		"config":   cfg,
	})
}
