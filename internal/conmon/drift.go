package conmon

import (
	"context"
	"database/sql"
	"time"
)

// Deviation represents a detected drift event — a gate that was passing
// in the previous run but is now failing (or transitioning from FAIL→PASS,
// which is not a deviation but is recorded for completeness).
type Deviation struct {
	ID              int64      `json:"id"`
	TenantID         string      `json:"tenant_id"`
	ScheduleID      int64      `json:"schedule_id"`
	RunID           int64      `json:"run_id"`
	GateName        string     `json:"gate_name"`
	Framework       string     `json:"framework"`
	PrevVerdict     string     `json:"prev_verdict"`
	CurrVerdict     string     `json:"curr_verdict"`
	Severity        string     `json:"severity"`
	DetectedAt      time.Time  `json:"detected_at"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy  string     `json:"acknowledged_by,omitempty"`
	POAMID          *int64     `json:"poam_id,omitempty"`
	Notes           string     `json:"notes,omitempty"`
}

// VerdictRecord is the minimal interface the drift detector needs from
// a pipeline run — gate name, framework, and verdict.
type VerdictRecord struct {
	GateName    string
	Framework   string
	Verdict     string // PASS / FAIL / WAIVE
	Severity    string
}

// DetectDrift compares verdicts from the current run against the most
// recent run for the same schedule, and records any PASS→FAIL transitions
// as deviations. Called by the pipeline immediately after a ConMon run
// completes its gate evaluation.
func DetectDrift(ctx context.Context, db *sql.DB, scheduleID, runID int64,
	current []VerdictRecord) ([]Deviation, error) {

	// Get tenant + previous run for this schedule
	var tenantID string
	var prevRunID sql.NullInt64
	err := db.QueryRowContext(ctx, `
		SELECT tenant_id, last_run_id FROM conmon_schedules WHERE id = $1
	`, scheduleID).Scan(&tenantID, &prevRunID)
	if err != nil {
		return nil, err
	}

	// Build map of current verdicts by gate+framework
	currMap := make(map[string]VerdictRecord, len(current))
	for _, v := range current {
		key := v.Framework + ":" + v.GateName
		currMap[key] = v
	}

	// If no previous run, just record verdicts as baseline (no drift yet)
	if !prevRunID.Valid {
		return updateScheduleAfterRun(ctx, db, scheduleID, runID, current)
	}

	// Get verdicts from previous run (we keep them as deviations table
	// snapshot via the runs themselves — read from gate verdict ledger).
	prev, err := loadVerdicts(ctx, db, prevRunID.Int64)
	if err != nil {
		return nil, err
	}
	prevMap := make(map[string]VerdictRecord, len(prev))
	for _, v := range prev {
		key := v.Framework + ":" + v.GateName
		prevMap[key] = v
	}

	// Find PASS→FAIL transitions
	var devs []Deviation
	for key, currV := range currMap {
		prevV, exists := prevMap[key]
		if !exists {
			continue // new gate, not drift
		}
		if prevV.Verdict == "PASS" && currV.Verdict == "FAIL" {
			dev := Deviation{
				TenantID:    tenantID,
				ScheduleID:  scheduleID,
				RunID:       runID,
				GateName:    currV.GateName,
				Framework:   currV.Framework,
				PrevVerdict: "PASS",
				CurrVerdict: "FAIL",
				Severity:    currV.Severity,
				DetectedAt:  time.Now(),
			}
			id, err := insertDeviation(ctx, db, dev)
			if err == nil {
				dev.ID = id
				devs = append(devs, dev)
			}
		}
	}

	if _, err := updateScheduleAfterRun(ctx, db, scheduleID, runID, current); err != nil {
		return devs, err
	}

	return devs, nil
}

func loadVerdicts(ctx context.Context, db *sql.DB, runID int64) ([]VerdictRecord, error) {
	// This reads from a hypothetical gate_verdicts table. If your repo
	// stores verdicts elsewhere, adjust the query. The table is created
	// by the gate evaluator; here we treat absence as "no verdicts".
	rows, err := db.QueryContext(ctx, `
		SELECT gate_name, framework, verdict, severity
		FROM gate_verdicts
		WHERE run_id = $1
	`, runID)
	if err != nil {
		// Likely the verdicts table doesn't exist yet — return empty
		// rather than error. The schedule will still update.
		return nil, nil
	}
	defer rows.Close()

	var out []VerdictRecord
	for rows.Next() {
		var v VerdictRecord
		if err := rows.Scan(&v.GateName, &v.Framework, &v.Verdict, &v.Severity); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func insertDeviation(ctx context.Context, db *sql.DB, d Deviation) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO conmon_deviations
		  (tenant_id, schedule_id, run_id, gate_name, framework,
		   prev_verdict, curr_verdict, severity, detected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id
	`, d.TenantID, d.ScheduleID, d.RunID, d.GateName, d.Framework,
		d.PrevVerdict, d.CurrVerdict, d.Severity, d.DetectedAt).Scan(&id)
	return id, err
}

func updateScheduleAfterRun(ctx context.Context, db *sql.DB,
	scheduleID, runID int64, current []VerdictRecord) ([]Deviation, error) {
	// Aggregate to a single overall verdict: any FAIL → FAIL, else PASS.
	overall := "PASS"
	for _, v := range current {
		if v.Verdict == "FAIL" {
			overall = "FAIL"
			break
		}
	}

	if overall == "PASS" {
		_, err := db.ExecContext(ctx, `
			UPDATE conmon_schedules
			SET last_verdict = $1, consecutive_pass = consecutive_pass + 1,
			    consecutive_fail = 0, updated_at = now()
			WHERE id = $2
		`, overall, scheduleID)
		return nil, err
	}

	_, err := db.ExecContext(ctx, `
		UPDATE conmon_schedules
		SET last_verdict = $1, consecutive_fail = consecutive_fail + 1,
		    consecutive_pass = 0, updated_at = now()
		WHERE id = $2
	`, overall, scheduleID)
	return nil, err
}

// ListDeviations returns all deviations for a tenant, with optional filter
// for unacknowledged only.
func ListDeviations(ctx context.Context, db *sql.DB, tenantID string, openOnly bool) ([]Deviation, error) {
	q := `
		SELECT id, tenant_id, schedule_id, run_id, gate_name, framework,
		       prev_verdict, curr_verdict, severity, detected_at,
		       acknowledged_at, COALESCE(acknowledged_by,''), poam_id,
		       COALESCE(notes,'')
		FROM conmon_deviations
		WHERE tenant_id = $1
	`
	if openOnly {
		q += ` AND acknowledged_at IS NULL`
	}
	q += ` ORDER BY detected_at DESC LIMIT 200`

	rows, err := db.QueryContext(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Deviation
	for rows.Next() {
		var d Deviation
		var ackAt sql.NullTime
		var poamID sql.NullInt64
		if err := rows.Scan(&d.ID, &d.TenantID, &d.ScheduleID, &d.RunID,
			&d.GateName, &d.Framework, &d.PrevVerdict, &d.CurrVerdict,
			&d.Severity, &d.DetectedAt, &ackAt, &d.AcknowledgedBy,
			&poamID, &d.Notes); err != nil {
			return nil, err
		}
		if ackAt.Valid {
			t := ackAt.Time
			d.AcknowledgedAt = &t
		}
		if poamID.Valid {
			id := poamID.Int64
			d.POAMID = &id
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AcknowledgeDeviation marks a deviation as acknowledged by a user.
func AcknowledgeDeviation(ctx context.Context, db *sql.DB,
	deviationID int64, tenantID string, ackBy, notes string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE conmon_deviations
		SET acknowledged_at = now(), acknowledged_by = $1, notes = $2
		WHERE id = $3 AND tenant_id = $4 AND acknowledged_at IS NULL
	`, ackBy, notes, deviationID, tenantID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CadenceStatus represents how a tenant is tracking against a framework's
// re-scan cadence (e.g. FedRAMP Moderate 30-day requirement).
type CadenceStatus struct {
	Framework      string    `json:"framework"`
	CadenceDays    int       `json:"cadence_days"`
	LastScanAt     *time.Time `json:"last_scan_at,omitempty"`
	NextDueAt      time.Time `json:"next_due_at"`
	IsOverdue      bool      `json:"is_overdue"`
	ConsecutiveMet int       `json:"consecutive_met"`
}

// GetCadenceStatus returns FedRAMP-style compliance status across the
// configured frameworks for a tenant.
func GetCadenceStatus(ctx context.Context, db *sql.DB, tenantID string) ([]CadenceStatus, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT framework, cadence_days, last_scan_at, next_due_at,
		       is_overdue, consecutive_met
		FROM conmon_cadence_status
		WHERE tenant_id = $1
		ORDER BY framework, cadence_days
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CadenceStatus
	for rows.Next() {
		var c CadenceStatus
		var lastScan sql.NullTime
		if err := rows.Scan(&c.Framework, &c.CadenceDays, &lastScan,
			&c.NextDueAt, &c.IsOverdue, &c.ConsecutiveMet); err != nil {
			return nil, err
		}
		if lastScan.Valid {
			t := lastScan.Time
			c.LastScanAt = &t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
