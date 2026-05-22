package handler

import (
	"context"
	"github.com/hibiken/asynq"
	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/pipeline"
)

// SetAsynqClient wires an asynq client into the Runs handler so that
// POST /vsp/run actually enqueues the job to the scanner worker.
// Call this from main() after creating the handler.
func (h *Runs) SetAsynqClient(client *asynq.Client) {
	h.asynq = client
}

// enqueueOrLog enqueues the scan job if asynq is wired, else logs a warning.
func (h *Runs) enqueueOrLog(rid, tenantID string, mode pipeline.Mode, profile pipeline.Profile, src, url string) {
	if h.asynq == nil {
		log.Warn().Str("rid", rid).Msg("asynq not configured — run scanner binary separately")
		return
	}
	payload := pipeline.JobPayload{
		RID: rid, TenantID: tenantID,
		Mode: mode, Profile: profile,
		Src: src, TargetURL: url,
	}
	if err := pipeline.EnqueueScan(h.asynq, payload); err != nil {
		log.Error().Err(err).Str("rid", rid).Msg("enqueue failed")
	} else {
		log.Info().Str("rid", rid).Msg("scan enqueued")
	}
}

// EnqueueDirect is called by the scheduler engine to trigger a scan.
func (h *Runs) EnqueueDirect(rid, tenantID string, mode pipeline.Mode, profile pipeline.Profile, src, url string) {
	// tools_total drives the FE progress bar AND the "X/Y" badge in the
	// run history table. It MUST match the actual number of tools the
	// worker will dispatch — owned by pipeline.ToolNamesForMode.
	//
	// Prior to 2026-05-11 a hand-maintained map here drifted:
	//   SCA=3   (real 8 — was missing osv-scanner/cosign/retire-js/syft/govulncheck)
	//   IAC=2   (real 3 — was missing hadolint)
	//   FULL_SOC=18 (real 26 — was missing phase4 + network groups)
	// The /vsp/run POST path was fixed on 2026-05-07 (runs.go:100) but
	// this scheduler-triggered enqueue was missed, so every cron-fired
	// FULL_SOC run showed "18/18" while the FE "New Scan" modal
	// advertised 26 tools — a visible mismatch end-users noticed.
	toolsTotal := len(pipeline.ToolNamesForMode(mode))
	if toolsTotal == 0 {
		toolsTotal = 3
	}
	h.DB.CreateRun(context.Background(), rid, tenantID, string(mode), string(profile), src, url, toolsTotal) //nolint:errcheck
	h.enqueueOrLog(rid, tenantID, mode, profile, src, url)
}
