// Package conmon implements continuous monitoring for VSP pipelines.
//
// FedRAMP requires that authorized systems re-validate their security
// posture on a defined cadence (30/60/90 days for Moderate baseline).
// ConMon orchestrates these re-runs, detects when previously-passed
// compliance gates begin to fail (drift), and auto-creates POA&M
// entries for the deviations.
package conmon

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Schedule represents a single ConMon entry — a target/mode pair that
// will be re-scanned on the configured cadence.
type Schedule struct {
	ID               int64     `json:"id"`
	TenantID         string     `json:"tenant_id"`
	Name             string    `json:"name"`
	Cadence          string    `json:"cadence"` // 30d / 60d / 90d / daily / weekly / custom
	CronExpr         string    `json:"cron_expr,omitempty"`
	Mode             string    `json:"mode"`
	TargetPath       string    `json:"target_path"`
	Enabled          bool      `json:"enabled"`
	LastRunAt        *time.Time `json:"last_run_at,omitempty"`
	LastRunID        *int64    `json:"last_run_id,omitempty"`
	LastVerdict      string    `json:"last_verdict,omitempty"`
	NextRunAt        time.Time `json:"next_run_at"`
	ConsecutivePass  int       `json:"consecutive_pass"`
	ConsecutiveFail  int       `json:"consecutive_fail"`
	CreatedAt        time.Time `json:"created_at"`
	CreatedBy        string    `json:"created_by,omitempty"`
}

// Scheduler runs as a background goroutine, polling the conmon_schedules
// table for due runs and triggering them through the existing pipeline.
type Scheduler struct {
	DB           *sql.DB
	TickInterval time.Duration  // how often to check for due runs
	RunTrigger   RunTriggerFunc // injected: triggers pipeline run
}

// RunTriggerFunc is the contract the gateway provides to actually
// kick off a pipeline run. Returns the run ID.
type RunTriggerFunc func(ctx context.Context, tenantID string, mode, targetPath string) (int64, error)

// NewScheduler constructs a Scheduler with sensible defaults.
func NewScheduler(db *sql.DB, trigger RunTriggerFunc) *Scheduler {
	return &Scheduler{
		DB:           db,
		TickInterval: 60 * time.Second,
		RunTrigger:   trigger,
	}
}

// Start runs until ctx is cancelled. Each tick, all due schedules are
// triggered. Run failures are logged but do not stop the scheduler.
func (s *Scheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(s.TickInterval)
	defer ticker.Stop()

	// Initial tick immediately so a freshly-created schedule fires
	// without waiting a full interval.
	s.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

func (s *Scheduler) tick(ctx context.Context) {
	due, err := s.dueSchedules(ctx)
	if err != nil {
		// In production this would emit to the platform logger.
		// Keeping silent here per audit policy: scheduler failures
		// must not crash the gateway.
		return
	}

	for _, sch := range due {
		s.triggerOne(ctx, sch)
	}
}

func (s *Scheduler) dueSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, tenant_id, name, cadence, cron_expr, mode, target_path,
		       enabled, last_run_at, last_run_id, last_verdict, next_run_at,
		       consecutive_pass, consecutive_fail, created_at, created_by
		FROM conmon_schedules
		WHERE enabled = true AND next_run_at <= now()
		ORDER BY next_run_at ASC
		LIMIT 50
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Schedule
	for rows.Next() {
		var s Schedule
		var cronExpr, lastVerdict, createdBy sql.NullString
		var lastRunAt sql.NullTime
		var lastRunID sql.NullInt64
		if err := rows.Scan(&s.ID, &s.TenantID, &s.Name, &s.Cadence, &cronExpr,
			&s.Mode, &s.TargetPath, &s.Enabled, &lastRunAt, &lastRunID,
			&lastVerdict, &s.NextRunAt, &s.ConsecutivePass, &s.ConsecutiveFail,
			&s.CreatedAt, &createdBy); err != nil {
			return nil, err
		}
		s.CronExpr = cronExpr.String
		s.LastVerdict = lastVerdict.String
		s.CreatedBy = createdBy.String
		if lastRunAt.Valid {
			t := lastRunAt.Time
			s.LastRunAt = &t
		}
		if lastRunID.Valid {
			id := lastRunID.Int64
			s.LastRunID = &id
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (s *Scheduler) triggerOne(ctx context.Context, sch Schedule) {
	if s.RunTrigger == nil {
		return
	}

	runID, err := s.RunTrigger(ctx, sch.TenantID, sch.Mode, sch.TargetPath)
	if err != nil {
		// Mark next_run_at to now+5min so we retry without locking us
		// into infinite-failure loops.
		_, _ = s.DB.ExecContext(ctx, `
			UPDATE conmon_schedules SET next_run_at = now() + interval '5 minutes',
			                            updated_at = now()
			WHERE id = $1
		`, sch.ID)
		return
	}

	// Compute next run time based on cadence. We update last_run_id;
	// last_verdict will be filled by the drift detector after the
	// pipeline finishes.
	next := nextRun(time.Now(), sch.Cadence)
	_, _ = s.DB.ExecContext(ctx, `
		UPDATE conmon_schedules
		SET last_run_id = $1, last_run_at = now(), next_run_at = $2,
		    updated_at = now()
		WHERE id = $3
	`, runID, next, sch.ID)
}

// nextRun computes the next scheduled time given a cadence string.
// 'custom' callers should use cron parsing instead.
func nextRun(from time.Time, cadence string) time.Time {
	switch cadence {
	case "daily":
		return from.Add(24 * time.Hour)
	case "weekly":
		return from.Add(7 * 24 * time.Hour)
	case "30d":
		return from.AddDate(0, 0, 30)
	case "60d":
		return from.AddDate(0, 0, 60)
	case "90d":
		return from.AddDate(0, 0, 90)
	default:
		// Conservative fallback — treat unknown cadences as 30d.
		return from.AddDate(0, 0, 30)
	}
}

// CreateSchedule inserts a new schedule and computes its first next_run_at.
func CreateSchedule(ctx context.Context, db *sql.DB, sch Schedule) (int64, error) {
	if sch.Cadence == "" {
		return 0, fmt.Errorf("cadence required")
	}
	if sch.Mode == "" {
		sch.Mode = "FULL"
	}
	if sch.TargetPath == "" {
		return 0, fmt.Errorf("target_path required")
	}

	first := nextRun(time.Now(), sch.Cadence)

	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO conmon_schedules
		  (tenant_id, name, cadence, cron_expr, mode, target_path,
		   enabled, next_run_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id
	`, sch.TenantID, sch.Name, sch.Cadence, nullString(sch.CronExpr),
		sch.Mode, sch.TargetPath, true, first, sch.CreatedBy).Scan(&id)
	return id, err
}

// ListSchedules returns all schedules for a tenant.
func ListSchedules(ctx context.Context, db *sql.DB, tenantID string) ([]Schedule, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, tenant_id, name, cadence, COALESCE(cron_expr,''), mode,
		       target_path, enabled, last_run_at, last_run_id,
		       COALESCE(last_verdict,''), next_run_at,
		       consecutive_pass, consecutive_fail, created_at,
		       COALESCE(created_by,'')
		FROM conmon_schedules
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Schedule
	for rows.Next() {
		var s Schedule
		var lastRunAt sql.NullTime
		var lastRunID sql.NullInt64
		if err := rows.Scan(&s.ID, &s.TenantID, &s.Name, &s.Cadence, &s.CronExpr,
			&s.Mode, &s.TargetPath, &s.Enabled, &lastRunAt, &lastRunID,
			&s.LastVerdict, &s.NextRunAt, &s.ConsecutivePass, &s.ConsecutiveFail,
			&s.CreatedAt, &s.CreatedBy); err != nil {
			return nil, err
		}
		if lastRunAt.Valid {
			t := lastRunAt.Time
			s.LastRunAt = &t
		}
		if lastRunID.Valid {
			id := lastRunID.Int64
			s.LastRunID = &id
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
