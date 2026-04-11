// internal/siem/ueba.go
// UEBA — User & Entity Behavior Analytics
// Baseline normal behavior, detect anomalies vs scan patterns
package siem

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/store"
)

// AnomalyType classifies detected behavioral anomalies.
type AnomalyType string

const (
	AnomalyScoreSpike     AnomalyType = "score_spike"
	AnomalyFindingsSurge  AnomalyType = "findings_surge"
	AnomalyGateFailStreak AnomalyType = "gate_fail_streak"
	AnomalyScanFrequency  AnomalyType = "scan_frequency"
	AnomalyNewCritical    AnomalyType = "new_critical_tool"
	AnomalyOffHoursScan   AnomalyType = "off_hours_scan"
	AnomalySLABreach      AnomalyType = "sla_breach"
)

// Anomaly is a detected behavioral deviation.
type Anomaly struct {
	Type       AnomalyType `json:"type"`
	Severity   string      `json:"severity"`
	Score      float64     `json:"score"` // 0-100 anomaly score
	Baseline   float64     `json:"baseline"`
	Current    float64     `json:"current"`
	Deviation  float64     `json:"deviation_pct"`
	Message    string      `json:"message"`
	Entity     string      `json:"entity"` // run_id, user, tool
	DetectedAt time.Time   `json:"detected_at"`
}

// Baseline holds statistical norms for a tenant.
type Baseline struct {
	TenantID       string
	AvgScore       float64
	StdScore       float64
	AvgFindings    float64
	StdFindings    float64
	AvgCritical    float64
	StdCritical    float64
	GatePassRate   float64
	AvgScansPerDay float64
	Tools          map[string]int // tool → finding count
	LastUpdated    time.Time
}

// UEBAEngine detects behavioral anomalies across scan runs.
type UEBAEngine struct {
	db       *store.DB
	tenantID string
	baseline *Baseline
}

func NewUEBAEngine(db *store.DB, tenantID string) *UEBAEngine {
	return &UEBAEngine{db: db, tenantID: tenantID}
}

// Analyze runs UEBA checks against recent scans and returns anomalies.
func (e *UEBAEngine) Analyze(ctx context.Context) ([]Anomaly, error) {
	if err := e.updateBaseline(ctx); err != nil {
		return nil, fmt.Errorf("ueba: baseline: %w", err)
	}
	var anomalies []Anomaly

	// Check 1: Score spike (drop or rise vs baseline)
	if a := e.checkScoreSpike(ctx); a != nil {
		anomalies = append(anomalies, *a)
	}
	// Check 2: Findings surge
	if a := e.checkFindingsSurge(ctx); a != nil {
		anomalies = append(anomalies, *a)
	}
	// Check 3: Gate FAIL streak
	if a := e.checkGateFailStreak(ctx); a != nil {
		anomalies = append(anomalies, *a)
	}
	// Check 4: Off-hours scans
	anomalies = append(anomalies, e.checkOffHoursScans(ctx)...)
	// Check 5: New tool with criticals
	anomalies = append(anomalies, e.checkNewCriticalTools(ctx)...)
	// Check 6: SLA breach
	if a := e.checkSLABreach(ctx); a != nil {
		anomalies = append(anomalies, *a)
	}

	if len(anomalies) > 0 {
		log.Info().
			Int("anomalies", len(anomalies)).
			Str("tenant", e.tenantID).
			Msg("ueba: anomalies detected")
	}
	return anomalies, nil
}

// updateBaseline recalculates statistical norms from last 30 days.
func (e *UEBAEngine) updateBaseline(ctx context.Context) error {
	b := &Baseline{TenantID: e.tenantID, LastUpdated: time.Now(), Tools: make(map[string]int)}

	// Score stats
	row := e.db.Pool().QueryRow(ctx, `
		SELECT AVG(COALESCE((summary->>'SCORE')::float,0)),
		       STDDEV(COALESCE((summary->>'SCORE')::float,0)),
		       AVG(COALESCE(total_findings,0)),
		       STDDEV(COALESCE(total_findings,0)),
		       AVG(COALESCE((summary->>'CRITICAL')::float,0)),
		       STDDEV(COALESCE((summary->>'CRITICAL')::float,0)),
		       COUNT(CASE WHEN gate='PASS' THEN 1 END)::float / NULLIF(COUNT(*),0)
		FROM runs
		WHERE tenant_id=$1
		  AND created_at > NOW() - INTERVAL '30 days'
		  AND status='DONE'`, e.tenantID)
	row.Scan(&b.AvgScore, &b.StdScore, &b.AvgFindings, &b.StdFindings, //nolint:errcheck
		&b.AvgCritical, &b.StdCritical, &b.GatePassRate)

	// Scan frequency
	e.db.Pool().QueryRow(ctx, `
		SELECT COUNT(*)::float / 30
		FROM runs
		WHERE tenant_id=$1
		  AND created_at > NOW() - INTERVAL '30 days'`, e.tenantID,
	).Scan(&b.AvgScansPerDay) //nolint:errcheck

	// Tool finding counts (baseline)
	rows, _ := e.db.Pool().Query(ctx, `
		SELECT tool, COUNT(*) FROM findings
		WHERE tenant_id=$1
		  AND created_at > NOW() - INTERVAL '30 days'
		GROUP BY tool`, e.tenantID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var tool string
			var cnt int
			if err := rows.Scan(&tool, &cnt); err != nil {
				log.Warn().Err(err).Msg("scan error")
			}
			b.Tools[tool] = cnt
		}
	}

	e.baseline = b
	return nil
}

func (e *UEBAEngine) checkScoreSpike(ctx context.Context) *Anomaly {
	if e.baseline == nil || e.baseline.AvgScore == 0 {
		return nil
	}
	var latestScore float64
	e.db.Pool().QueryRow(ctx, `
		SELECT COALESCE((summary->>'SCORE')::float,0)
		FROM runs WHERE tenant_id=$1 AND status='DONE'
		ORDER BY created_at DESC LIMIT 1`, e.tenantID,
	).Scan(&latestScore) //nolint:errcheck

	if latestScore == 0 {
		return nil
	}
	drop := e.baseline.AvgScore - latestScore
	threshold := e.baseline.StdScore * 2
	if threshold < 10 {
		threshold = 10
	}

	if drop > threshold {
		devPct := drop / e.baseline.AvgScore * 100
		sev := "MEDIUM"
		if drop > threshold*2 {
			sev = "HIGH"
		}
		if drop > threshold*3 {
			sev = "CRITICAL"
		}
		return &Anomaly{
			Type:       AnomalyScoreSpike,
			Severity:   sev,
			Score:      math.Min(100, drop/e.baseline.AvgScore*100),
			Baseline:   e.baseline.AvgScore,
			Current:    latestScore,
			Deviation:  devPct,
			Message:    fmt.Sprintf("Security score dropped %.0f pts (baseline %.0f, now %.0f)", drop, e.baseline.AvgScore, latestScore),
			Entity:     "security_score",
			DetectedAt: time.Now(),
		}
	}
	return nil
}

func (e *UEBAEngine) checkFindingsSurge(ctx context.Context) *Anomaly {
	if e.baseline == nil || e.baseline.AvgFindings == 0 {
		return nil
	}
	var latest float64
	e.db.Pool().QueryRow(ctx, `
		SELECT COALESCE(total_findings,0)
		FROM runs WHERE tenant_id=$1 AND status='DONE'
		ORDER BY created_at DESC LIMIT 1`, e.tenantID,
	).Scan(&latest) //nolint:errcheck

	threshold := e.baseline.AvgFindings + e.baseline.StdFindings*2
	if threshold < 10 {
		threshold = 10
	}
	if latest > threshold {
		devPct := (latest - e.baseline.AvgFindings) / e.baseline.AvgFindings * 100
		return &Anomaly{
			Type:       AnomalyFindingsSurge,
			Severity:   "HIGH",
			Score:      math.Min(100, devPct/2),
			Baseline:   e.baseline.AvgFindings,
			Current:    latest,
			Deviation:  devPct,
			Message:    fmt.Sprintf("Findings count %.0f exceeds baseline %.0f by %.0f%%", latest, e.baseline.AvgFindings, devPct),
			Entity:     "findings_count",
			DetectedAt: time.Now(),
		}
	}
	return nil
}

func (e *UEBAEngine) checkGateFailStreak(ctx context.Context) *Anomaly {
	rows, err := e.db.Pool().Query(ctx, `
		SELECT gate FROM runs
		WHERE tenant_id=$1 AND status='DONE'
		ORDER BY created_at DESC LIMIT 5`, e.tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	streak := 0
	for rows.Next() {
		var gate string
		if err := rows.Scan(&gate); err != nil {
			log.Warn().Err(err).Msg("scan error")
		}
		if gate == "FAIL" {
			streak++
		} else {
			break
		}
	}
	if streak >= 3 {
		sev := "HIGH"
		if streak >= 5 {
			sev = "CRITICAL"
		}
		return &Anomaly{
			Type:       AnomalyGateFailStreak,
			Severity:   sev,
			Score:      math.Min(100, float64(streak)*20),
			Current:    float64(streak),
			Baseline:   e.baseline.GatePassRate * 100,
			Deviation:  float64(streak) * 20,
			Message:    fmt.Sprintf("%d consecutive gate FAILs detected (baseline pass rate: %.0f%%)", streak, e.baseline.GatePassRate*100),
			Entity:     "gate_decisions",
			DetectedAt: time.Now(),
		}
	}
	return nil
}

func (e *UEBAEngine) checkOffHoursScans(ctx context.Context) []Anomaly {
	rows, err := e.db.Pool().Query(ctx, `
		SELECT rid, created_at
		FROM runs
		WHERE tenant_id=$1
		  AND created_at > NOW() - INTERVAL '24 hours'
		  AND EXTRACT(HOUR FROM created_at AT TIME ZONE 'UTC') NOT BETWEEN 7 AND 19
		  AND status='DONE'
		ORDER BY created_at DESC LIMIT 5`, e.tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var anomalies []Anomaly
	for rows.Next() {
		var rid string
		var ts time.Time
		if err := rows.Scan(&rid, &ts); err != nil {
			log.Warn().Err(err).Msg("scan error")
		}
		h := ts.UTC().Hour()
		anomalies = append(anomalies, Anomaly{
			Type:       AnomalyOffHoursScan,
			Severity:   "LOW",
			Score:      25,
			Message:    fmt.Sprintf("Scan triggered at %02d:00 UTC (off-hours): %s", h, rid),
			Entity:     rid,
			DetectedAt: time.Now(),
		})
	}
	return anomalies
}

func (e *UEBAEngine) checkNewCriticalTools(ctx context.Context) []Anomaly {
	if e.baseline == nil {
		return nil
	}
	// Tools with criticals in last 24h that had none in baseline
	rows, err := e.db.Pool().Query(ctx, `
		SELECT tool, COUNT(*) as cnt
		FROM findings
		WHERE tenant_id=$1
		  AND severity='CRITICAL'
		  AND created_at > NOW() - INTERVAL '24 hours'
		GROUP BY tool`, e.tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var anomalies []Anomaly
	for rows.Next() {
		var tool string
		var cnt int
		if err := rows.Scan(&tool, &cnt); err != nil {
			log.Warn().Err(err).Msg("scan error")
		}
		if _, existed := e.baseline.Tools[tool]; !existed && cnt > 0 {
			anomalies = append(anomalies, Anomaly{
				Type:       AnomalyNewCriticalTool,
				Severity:   "HIGH",
				Score:      70,
				Current:    float64(cnt),
				Baseline:   0,
				Message:    fmt.Sprintf("New tool '%s' detected %d CRITICAL findings (not seen in baseline)", tool, cnt),
				Entity:     tool,
				DetectedAt: time.Now(),
			})
		}
	}
	return anomalies
}

func (e *UEBAEngine) checkSLABreach(ctx context.Context) *Anomaly {
	var breached int
	e.db.Pool().QueryRow(ctx, `
		SELECT COUNT(*)
		FROM remediations r
		JOIN findings f ON f.id=r.finding_id
		WHERE r.tenant_id=$1
		  AND r.status='open'
		  AND (
		        (f.severity='CRITICAL' AND r.created_at < NOW() - INTERVAL '3 days') OR
		        (f.severity='HIGH'     AND r.created_at < NOW() - INTERVAL '14 days') OR
		        (f.severity='MEDIUM'   AND r.created_at < NOW() - INTERVAL '30 days')
		      )`, e.tenantID,
	).Scan(&breached) //nolint:errcheck
	if breached > 0 {
		sev := "MEDIUM"
		if breached >= 5 {
			sev = "HIGH"
		}
		if breached >= 10 {
			sev = "CRITICAL"
		}
		return &Anomaly{
			Type:       AnomalySLABreach,
			Severity:   sev,
			Score:      math.Min(100, float64(breached)*10),
			Current:    float64(breached),
			Message:    fmt.Sprintf("%d findings have exceeded their SLA deadline without remediation", breached),
			Entity:     "remediations",
			DetectedAt: time.Now(),
		}
	}
	return nil
}

// AnomalyNewCriticalTool = AnomalyNewCritical (same value, kept for code using this name)
const AnomalyNewCriticalTool AnomalyType = AnomalyNewCritical

// RunUEBA is the entry point for the UEBA background worker.
// Call this on a schedule (e.g. every 15 minutes).
func RunUEBA(ctx context.Context, db *store.DB) {
	// Get all active tenants
	rows, err := db.Pool().Query(ctx, `SELECT id FROM tenants WHERE active=true`)
	if err != nil {
		log.Error().Err(err).Msg("ueba: list tenants failed")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			log.Warn().Err(err).Msg("scan error")
		}
		engine := NewUEBAEngine(db, tenantID)
		anomalies, err := engine.Analyze(ctx)
		if err != nil {
			log.Error().Err(err).Str("tenant", tenantID).Msg("ueba: analysis failed")
			continue
		}
		// Persist anomalies as incidents
		for _, a := range anomalies {
			if a.Score < 30 {
				continue
			} // Only create incidents for significant anomalies
			// Dedup: skip if same title already open in last 6h
			var existing int
			// Truncate title to 200 chars for efficient index lookup
			title := a.Message
			if len(title) > 200 {
				title = title[:200]
			}
			// Dedup by anomaly type — not title (title changes as counts change)
			anomalyType := string(a.Type)
			db.Pool().QueryRow(ctx, `
				SELECT COUNT(*) FROM incidents
				WHERE tenant_id=$1
				  AND source_refs::text LIKE '%' || $2 || '%'
				  AND status='open'
				  AND created_at > NOW() - INTERVAL '6 hours'`,
				tenantID, anomalyType).Scan(&existing) //nolint:errcheck
			if existing > 0 {
				continue
			}
			// Truncate title consistently
			if len(title) == 0 {
				title = a.Message
			}
			if len(title) > 200 {
				title = title[:200]
			}
			db.Pool().Exec(ctx, `
				INSERT INTO incidents
					(tenant_id, title, severity, status, source_refs)
				VALUES ($1,$2,$3,'open',$4)`,
				tenantID, title, a.Severity,
				fmt.Sprintf(`{"type":"%s","score":%.1f,"entity":"%s"}`, a.Type, a.Score, a.Entity),
			) //nolint:errcheck
		}
	}
}
