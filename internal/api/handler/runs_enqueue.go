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
	// Sync với RunnersFor() — SECRETS:3(gitleaks+secretcheck+trufflehog), SCA:3(grype+trivy+license)
	toolsTotal := map[string]int{
		"SAST":     4,  // bandit+semgrep+codeql+gosec
		"SCA":      3,  // grype+trivy+license
		"SECRETS":  3,  // gitleaks+secretcheck+trufflehog
		"IAC":      2,  // kics+checkov
		"DAST":     3,  // nikto+nuclei+sslscan
		"NETWORK":  3,  // sslscan+nmap+netcap
		"FULL":     17, // all unique tools
		"FULL_SOC": 18, // all unique tools incl netcap
	}[string(mode)]
	if toolsTotal == 0 {
		toolsTotal = 3
	}
	h.DB.CreateRun(context.Background(), rid, tenantID, string(mode), string(profile), src, url, toolsTotal) //nolint:errcheck
	h.enqueueOrLog(rid, tenantID, mode, profile, src, url)
}
