// Package handler — KPI sanity watchdog (Sprint 8.7).
//
// The kpi_sanity endpoint is a probe; this file is the periodic process
// that runs the same checks every interval, writes failures to
// audit_log as KPI_SANITY_FAILED, and (when a notifier is wired) fires
// an alert. Pre-Sprint-8.7 a regression in the KPI math could sit
// undetected until a customer complained — now CI + the watchdog
// catch it within minutes.
//
// We do not write a successful run to audit_log: that would balloon
// the chain. Failures only.
package handler

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/gate"
	"github.com/vsp/platform/internal/scanner"
	"github.com/vsp/platform/internal/store"
)

// RunKPIWatchdog blocks until ctx is cancelled. Spawn from gateway main.
// The first tick fires immediately so a deployment that breaks the KPI
// math fails the watchdog at boot, not 5 minutes later.
func RunKPIWatchdog(ctx context.Context, db *store.DB, tick time.Duration) {
	if tick <= 0 {
		tick = 5 * time.Minute
	}
	log.Info().Dur("interval", tick).Msg("kpi watchdog started")
	t := time.NewTicker(tick)
	defer t.Stop()
	// Immediate first run.
	checkKPIInvariants(ctx, db)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			checkKPIInvariants(ctx, db)
		}
	}
}

// checkKPIInvariants runs the same probes as /api/v1/kpi/sanity but in-
// process. Failures go to audit_log so SOC dashboards surface them.
func checkKPIInvariants(ctx context.Context, db *store.DB) {
	failures := []map[string]any{}

	// Grade unification probes.
	probes := []struct {
		s    scanner.Summary
		want string
		why  string
	}{
		{scanner.Summary{}, "A+", "clean scan must be A+"},
		{scanner.Summary{Critical: 1}, "F", "any critical must be F"},
		{scanner.Summary{HasSecrets: true}, "F", "live secrets must be F"},
	}
	for _, p := range probes {
		if got := gate.Posture(p.s); got != p.want {
			failures = append(failures, map[string]any{
				"check":  "grade_unification",
				"reason": p.why,
				"got":    got,
				"want":   p.want,
			})
		}
	}

	// Score monotonicity — strictly decreasing as count grows.
	a := gate.Score(scanner.Summary{High: 5})
	b := gate.Score(scanner.Summary{High: 50})
	c := gate.Score(scanner.Summary{High: 500})
	if !(a > b && b > c) {
		failures = append(failures, map[string]any{
			"check":  "score_monotonic",
			"reason": "score must decrease as finding count grows",
			"high_5": a, "high_50": b, "high_500": c,
		})
	}

	if len(failures) == 0 {
		return // healthy — no audit noise.
	}

	// One row per audit_log entry; each failure carries its own resource
	// blob so the SOC panel can link "what's wrong" without parsing the
	// payload column manually.
	body, _ := json.Marshal(failures)
	_, err := db.Pool().Exec(ctx,
		`INSERT INTO audit_log (tenant_id, action, resource, payload, hash, prev_hash)
		 SELECT id, 'KPI_SANITY_FAILED',
		        'kpi_watchdog/' || $1, $2::jsonb, '', ''
		   FROM tenants
		  WHERE active = true LIMIT 1`,
		time.Now().UTC().Format(time.RFC3339), body)
	if err != nil {
		log.Warn().Err(err).Msg("kpi watchdog: audit insert failed")
		return
	}
	log.Warn().
		Int("failures", len(failures)).
		Msg("kpi watchdog: invariants violated — see audit_log KPI_SANITY_FAILED rows")
}
