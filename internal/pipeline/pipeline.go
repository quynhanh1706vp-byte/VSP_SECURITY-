package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/scanner"
	"github.com/vsp/platform/internal/scanner/bandit"
	"github.com/vsp/platform/internal/scanner/codeql"
	"github.com/vsp/platform/internal/scanner/gitleaks"
	"github.com/vsp/platform/internal/scanner/grype"
	"github.com/vsp/platform/internal/scanner/checkov"
	"github.com/vsp/platform/internal/scanner/kics"
	"github.com/vsp/platform/internal/scanner/nikto"
	"github.com/vsp/platform/internal/scanner/nuclei"
	"github.com/vsp/platform/internal/scanner/semgrep"
	"github.com/vsp/platform/internal/scanner/trivy"
)

// ── Status ────────────────────────────────────────────────────────────────────

type Status string

const (
	StatusQueued    Status = "QUEUED"
	StatusRunning   Status = "RUNNING"
	StatusDone      Status = "DONE"
	StatusFailed    Status = "FAILED"
	StatusCancelled Status = "CANCELLED"
)

// ── Mode / Profile ────────────────────────────────────────────────────────────

type Mode string

const (
	ModeSAST    Mode = "SAST"
	ModeDAST    Mode = "DAST"
	ModeSCA     Mode = "SCA"
	ModeSecrets Mode = "SECRETS"
	ModeIAC     Mode = "IAC"
	ModeFull    Mode = "FULL"
)

type Profile string

const (
	ProfileFast    Profile = "FAST"
	ProfileExt     Profile = "EXT"
	ProfileAggr    Profile = "AGGR"
	ProfilePremium Profile = "PREMIUM"
	ProfileFull    Profile = "FULL"
	ProfileFullSOC Profile = "FULL_SOC"
)

// ── Run ───────────────────────────────────────────────────────────────────────

// Run is the canonical representation of one scan job.
// Stored in DB table `runs` and used as the job payload.
type Run struct {
	ID        string    `json:"id"`         // UUID
	RID       string    `json:"rid"`        // human-readable: RID_VSPGO_RUN_YYYYMMDD_HHMMSS_xxxxxxxx
	TenantID  string    `json:"tenant_id"`
	Mode      Mode      `json:"mode"`
	Profile   Profile   `json:"profile"`
	Src       string    `json:"src"`
	TargetURL string    `json:"target_url"`
	Status    Status    `json:"status"`
	ToolsDone int       `json:"tools_done"`
	ToolsTotal int      `json:"tools_total"`
	CreatedAt time.Time `json:"created_at"`
	StartedAt *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// ── JobPayload ────────────────────────────────────────────────────────────────

// JobPayload is serialised into the asynq task and consumed by the worker.
type JobPayload struct {
	RunID     string            `json:"run_id"`
	RID       string            `json:"rid"`
	TenantID  string            `json:"tenant_id"`
	Mode      Mode              `json:"mode"`
	Profile   Profile           `json:"profile"`
	Src       string            `json:"src"`
	TargetURL string            `json:"target_url"`
	ExtraArgs map[string][]string `json:"extra_args,omitempty"`
}

// ── ToolSet — select runners based on mode ────────────────────────────────────

// RunnersFor returns the set of tool runners appropriate for the given mode.
// This is the single place that controls which tools run per mode.
func RunnersFor(mode Mode) []scanner.Runner {
	sast := []scanner.Runner{
		bandit.New(),
		semgrep.New(),
		codeql.New(),
	}
	sca := []scanner.Runner{
		grype.New(),
		trivy.New(),
	}
	secrets := []scanner.Runner{
		gitleaks.New(),
	}
	iac := []scanner.Runner{
		kics.New(),
		checkov.New(),
	}
	dast := []scanner.Runner{
		nikto.New(),
		nuclei.New(),
	}

	switch mode {
	case ModeSAST:
		return sast
	case ModeSCA:
		return sca
	case ModeSecrets:
		return secrets
	case ModeIAC:
		return iac
	case ModeDAST:
		return dast
	case ModeFull:
		all := make([]scanner.Runner, 0, 9)
		all = append(all, sast...)
		all = append(all, sca...)
		all = append(all, secrets...)
		all = append(all, iac...)
		all = append(all, dast...)
		return all
	default:
		// Default: SAST + SCA + Secrets (safe for most repos)
		r := make([]scanner.Runner, 0, 6)
		r = append(r, sast...)
		r = append(r, sca...)
		r = append(r, secrets...)
		return r
	}
}

// ── Executor ─────────────────────────────────────────────────────────────────

// Executor runs a pipeline job: selects tools, executes them, returns results.
// The caller is responsible for persisting Run state and Findings to the DB.
type Executor struct {
	// OnProgress is called after each tool completes (for real-time updates).
	// May be nil.
	OnProgress func(toolName string, done int, total int, findings int)
}

// ExecuteResult is returned by Execute.
type ExecuteResult struct {
	Findings   []scanner.Finding
	ToolErrors map[string]error
	Summary    scanner.Summary
	Duration   time.Duration
}

// Execute runs all tools for the given payload and returns the merged result.
// It does NOT write to the database — that is the caller's responsibility.
func (e *Executor) Execute(ctx context.Context, payload JobPayload) (*ExecuteResult, error) {
	runners := RunnersFor(payload.Mode)
	if len(runners) == 0 {
		return nil, fmt.Errorf("no runners available for mode %s", payload.Mode)
	}

	opts := scanner.RunOpts{
		Src:       payload.Src,
		URL:       payload.TargetURL,
		Mode:      string(payload.Mode),
		ExtraArgs: payload.ExtraArgs,
	}

	log.Info().
		Str("rid", payload.RID).
		Str("mode", string(payload.Mode)).
		Int("tools", len(runners)).
		Msg("pipeline starting")

	start := time.Now()

	// Run all tools concurrently; OnProgress fires as results come in.
	allFindings, details := e.runWithProgress(ctx, runners, opts)

	toolErrors := make(map[string]error)
	for _, d := range details {
		if d.Err != nil {
			toolErrors[d.Tool] = d.Err
			log.Warn().
				Str("rid", payload.RID).
				Str("tool", d.Tool).
				Err(d.Err).
				Msg("tool failed")
		} else {
			log.Info().
				Str("rid", payload.RID).
				Str("tool", d.Tool).
				Int("findings", len(d.Findings)).
				Dur("duration", d.Duration).
				Msg("tool done")
		}
	}

	return &ExecuteResult{
		Findings:   allFindings,
		ToolErrors: toolErrors,
		Summary:    scanner.Summarise(allFindings),
		Duration:   time.Since(start),
	}, nil
}

// runWithProgress wraps scanner.RunAll with per-tool progress callbacks.
func (e *Executor) runWithProgress(ctx context.Context, runners []scanner.Runner, opts scanner.RunOpts) ([]scanner.Finding, []scanner.RunResult) {
	if e.OnProgress == nil {
		return scanner.RunAll(ctx, runners, opts)
	}

	results := make(chan scanner.RunResult, len(runners))
	for _, r := range runners {
		r := r
		go func() {
			tctx, cancel := context.WithTimeout(ctx, opts.TimeoutOrDefault())
			defer cancel()
			start := time.Now()
			findings, err := r.Run(tctx, opts)
			results <- scanner.RunResult{
				Tool:     r.Name(),
				Findings: findings,
				Err:      err,
				Duration: time.Since(start),
			}
		}()
	}

	var allFindings []scanner.Finding
	var details []scanner.RunResult
	done := 0
	for range runners {
		res := <-results
		done++
		details = append(details, res)
		if res.Err == nil {
			allFindings = append(allFindings, res.Findings...)
		}
		e.OnProgress(res.Tool, done, len(runners), len(allFindings))
	}
	return allFindings, details
}
