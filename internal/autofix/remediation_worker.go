// =====================================================================
// H3.U Remediation Worker — auto-populate remediations from findings
// File: internal/autofix/remediation_worker.go
// =====================================================================

package autofix

import (
	"context"
	"database/sql"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/telemetry"
)

const (
	remediationPollInterval = 5 * time.Minute
	remediationBatchSize    = 500
)

// HealthTicker — minimal interface for liveness reporting (avoids import cycle).
type HealthTicker interface {
	Tick(processed int, errs int)
}

type nopHealth struct{}

func (nopHealth) Tick(int, int) {}

// StartRemediationWorker — call from main.go after p4DB init.
// health may be nil; pass a real WorkerHealth for /health/remediation endpoint.
func StartRemediationWorker(ctx context.Context, db *sql.DB, health HealthTicker) {
	if health == nil {
		health = nopHealth{}
	}
	g := telemetry.G()

	log.Info().
		Dur("interval", remediationPollInterval).
		Int("batch", remediationBatchSize).
		Msg("[H3.U] remediation worker starting")

	runOnce := func() {
		start := time.Now()
		inserted, resolved, errs := runRemediationCycle(ctx, db)
		dur := time.Since(start).Seconds()

		g.CounterInc("remediation_iterations_total", nil)
		if inserted > 0 {
			g.CounterAdd("remediations_inserted_total", nil, uint64(inserted))
		}
		if resolved > 0 {
			g.CounterAdd("remediations_resolved_total", nil, uint64(resolved))
		}
		if errs > 0 {
			g.CounterAdd("remediation_errors_total", nil, uint64(errs))
		}
		g.HistogramObserve("remediation_cycle_duration_seconds", dur, nil)
		health.Tick(inserted+resolved, errs)
	}

	go func() {
		runOnce()
		t := time.NewTicker(remediationPollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("[H3.U] remediation worker stopped")
				return
			case <-t.C:
				runOnce()
			}
		}
	}()
}

func runRemediationCycle(ctx context.Context, db *sql.DB) (inserted, resolved, errs int) {
	cycleCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	var err error
	inserted, err = insertNewItems(cycleCtx, db)
	if err != nil {
		log.Error().Err(err).Msg("[H3.U] insert new items failed")
		errs++
	}

	resolved, err = markResolvedItems(cycleCtx, db)
	if err != nil {
		log.Error().Err(err).Msg("[H3.U] mark resolved failed")
		errs++
	}

	if inserted > 0 || resolved > 0 {
		log.Info().
			Int("inserted", inserted).
			Int("resolved", resolved).
			Msg("[H3.U] remediation cycle done")
	}
	return inserted, resolved, errs
}

func insertNewItems(ctx context.Context, db *sql.DB) (int, error) {
	res, err := db.ExecContext(ctx, `
		INSERT INTO remediations  /* H3U-fixed */
			(finding_id, run_id, status, priority, created_at, updated_at)
		SELECT
			f.id,
			f.run_id,
			'open' AS status,
			LOWER(f.severity) AS priority,
			NOW(), NOW()
		FROM findings f
		WHERE f.severity IN ('CRITICAL', 'HIGH')
		  AND NOT EXISTS (
			  SELECT 1 FROM remediations r WHERE r.finding_id = f.id
		  )
		LIMIT $1
	`, remediationBatchSize)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func markResolvedItems(ctx context.Context, db *sql.DB) (int, error) {
	res, err := db.ExecContext(ctx, `
		WITH latest_runs AS (
			SELECT DISTINCT ON (tool) tool, run_id
			FROM findings
			ORDER BY tool, created_at DESC
		),
		latest_fingerprints AS (
			SELECT f.fingerprint
			FROM findings f
			JOIN latest_runs lr ON lr.tool = f.tool AND lr.run_id = f.run_id
		)
		UPDATE remediations r
		SET status = 'resolved',
		    resolved_at = NOW(),
		    resolved_by = 'auto-h3u-worker',
		    updated_at = NOW(),
		    notes = COALESCE(notes, '') ||
		              CASE WHEN notes IS NOT NULL AND notes != ''
		                   THEN E'\n[H3.U] auto-resolved: finding no longer in latest scan'
		                   ELSE '[H3.U] auto-resolved: finding no longer in latest scan'
		              END
		FROM findings f
		WHERE r.finding_id = f.id
		  AND r.status = 'open'
		  AND f.fingerprint NOT IN (SELECT fingerprint FROM latest_fingerprints)
	`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
