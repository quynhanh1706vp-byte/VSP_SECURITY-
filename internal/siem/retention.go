package siem

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/store"
)

// RetentionConfig defines retention periods per data type.
type RetentionConfig struct {
	LogEventsDays    int // default 90
	IncidentsDays    int // default 365
	PlaybookRunsDays int // default 180
	IOCExpiredDays   int // default 30
}

func DefaultRetention() RetentionConfig {
	return RetentionConfig{
		LogEventsDays:    90,
		IncidentsDays:    365,
		PlaybookRunsDays: 180,
		IOCExpiredDays:   30,
	}
}

// RunRetention archives/deletes old data. Run daily.
func RunRetention(ctx context.Context, db *store.DB, cfg RetentionConfig) {
	now := time.Now()
	log.Info().Msg("retention: starting cleanup")

	// 1. Archive old log events
	tag, err := db.Pool().Exec(ctx, `
		DELETE FROM log_events
		WHERE created_at < NOW() - make_interval(days => $1)`,
		cfg.LogEventsDays)
	if err != nil {
		log.Error().Err(err).Msg("retention: log_events cleanup failed")
	} else {
		log.Info().Int64("deleted", tag.RowsAffected()).
			Msg("retention: log_events cleaned")
	}

	// 2. Close stale incidents (open > 365 days)
	tag, err = db.Pool().Exec(ctx, `
		UPDATE incidents
		SET status = 'archived', updated_at = NOW()
		WHERE status = 'open'
		  AND created_at < NOW() - make_interval(days => $1)`,
		cfg.IncidentsDays)
	if err != nil {
		log.Error().Err(err).Msg("retention: incidents cleanup failed")
	} else {
		log.Info().Int64("archived", tag.RowsAffected()).
			Msg("retention: incidents archived")
	}

	// 3. Delete old playbook runs
	tag, err = db.Pool().Exec(ctx, `
		DELETE FROM playbook_runs
		WHERE started_at < NOW() - make_interval(days => $1)`,
		cfg.PlaybookRunsDays)
	if err != nil {
		log.Error().Err(err).Msg("retention: playbook_runs cleanup failed")
	} else {
		log.Info().Int64("deleted", tag.RowsAffected()).
			Msg("retention: playbook_runs cleaned")
	}

	// 4. Delete expired IOCs
	tag, err = db.Pool().Exec(ctx, `
		DELETE FROM iocs
		WHERE expires_at IS NOT NULL
		  AND expires_at < NOW()`)
	if err != nil {
		log.Error().Err(err).Msg("retention: iocs cleanup failed")
	} else {
		log.Info().Int64("deleted", tag.RowsAffected()).
			Msg("retention: expired IOCs cleaned")
	}

	// 5. Vacuum stats
	log.Info().
		Str("duration", time.Since(now).String()).
		Msg("retention: cleanup complete")
}

// StartRetentionWorker runs retention daily at 03:00 UTC.
func StartRetentionWorker(ctx context.Context, db *store.DB) {
	cfg := DefaultRetention()
	// Run once on startup after 10s delay
	go func() {
		time.Sleep(10 * time.Second)
		RunRetention(ctx, db, cfg)
	}()
	// Then daily at 03:00 UTC
	go func() {
		for {
			now := time.Now().UTC()
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 3, 0, 0, 0, time.UTC)
			wait := next.Sub(now)
			log.Info().Str("next_run", next.Format("2006-01-02 03:00 UTC")).
				Msg("retention: next cleanup scheduled")
			select {
			case <-time.After(wait):
				RunRetention(ctx, db, cfg)
			case <-ctx.Done():
				return
			}
		}
	}()
	log.Info().Msg("retention: worker started — daily at 03:00 UTC")
}
