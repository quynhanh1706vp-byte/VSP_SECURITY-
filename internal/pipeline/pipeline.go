package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/scanner"
	"github.com/vsp/platform/internal/scanner/bandit"
	"github.com/vsp/platform/internal/scanner/checkov"
	"github.com/vsp/platform/internal/scanner/codeql"
	"github.com/vsp/platform/internal/scanner/gitleaks"
	"github.com/vsp/platform/internal/scanner/grype"
	"github.com/vsp/platform/internal/scanner/hadolint"
	"github.com/vsp/platform/internal/scanner/kics"
	"github.com/vsp/platform/internal/scanner/license"
	"github.com/vsp/platform/internal/scanner/nikto"
	"github.com/vsp/platform/internal/scanner/nmap"
	"github.com/vsp/platform/internal/scanner/nuclei"
	"github.com/vsp/platform/internal/scanner/secretcheck"
	"github.com/vsp/platform/internal/scanner/semgrep"
	"github.com/vsp/platform/internal/scanner/sslscan"
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
	ModeFullSOC Mode = "FULL_SOC"
	ModeNetwork Mode = "NETWORK"
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
	ID         string     `json:"id"`  // UUID
	RID        string     `json:"rid"` // human-readable: RID_VSPGO_RUN_YYYYMMDD_HHMMSS_xxxxxxxx
	TenantID   string     `json:"tenant_id"`
	Mode       Mode       `json:"mode"`
	Profile    Profile    `json:"profile"`
	Src        string     `json:"src"`
	TargetURL  string     `json:"target_url"`
	Status     Status     `json:"status"`
	ToolsDone  int        `json:"tools_done"`
	ToolsTotal int        `json:"tools_total"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// ── JobPayload ────────────────────────────────────────────────────────────────

// JobPayload is serialised into the asynq task and consumed by the worker.
type JobPayload struct {
	RunID      string              `json:"run_id"`
	RID        string              `json:"rid"`
	TenantID   string              `json:"tenant_id"`
	Mode       Mode                `json:"mode"`
	Profile    Profile             `json:"profile"`
	Src        string              `json:"src"`
	TargetURL  string              `json:"target_url"`
	ExtraArgs  map[string][]string `json:"extra_args,omitempty"`
	TimeoutSec int                 `json:"timeout_sec,omitempty"`
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
		license.NewRunner(),
	}
	secrets := []scanner.Runner{
		gitleaks.New(),
		secretcheck.NewRunner(),
	}
	iac := []scanner.Runner{
		kics.New(),
		checkov.New(),
		hadolint.New(), // Dockerfile linting — CIS Docker Benchmark
	}
	dast := []scanner.Runner{
		nikto.New(),
		nuclei.New(),
		sslscan.New(),
		nmap.New(),
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
	case ModeNetwork:
		return []scanner.Runner{sslscan.New()}
	case ModeFull, ModeFullSOC:
		// FULL and FULL_SOC both run all scanners.
		// FULL_SOC additionally feeds findings into SIEM correlation (handled downstream).
		seen := make(map[string]bool)
		all := make([]scanner.Runner, 0, 15)
		for _, group := range [][]scanner.Runner{sast, sca, secrets, iac, dast} {
			for _, r := range group {
				if !seen[r.Name()] {
					seen[r.Name()] = true
					all = append(all, r)
				}
			}
		}
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
		Src:        payload.Src,
		URL:        payload.TargetURL,
		Mode:       string(payload.Mode),
		ExtraArgs:  payload.ExtraArgs,
		TimeoutSec: payload.TimeoutSec,
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

// ExecuteWith runs pipeline with an explicit runner list (used by worker for profile filtering).
func (e *Executor) ExecuteWith(ctx context.Context, payload JobPayload, runners []scanner.Runner) (*ExecuteResult, error) {
	if len(runners) == 0 {
		return nil, fmt.Errorf("no runners provided for mode %s profile %s", payload.Mode, payload.Profile)
	}
	opts := scanner.RunOpts{
		Src:       payload.Src,
		URL:       payload.TargetURL,
		Mode:      string(payload.Mode),
		ExtraArgs: payload.ExtraArgs,
	}
	start := time.Now()
	allFindings, details := e.runWithProgress(ctx, runners, opts)
	toolErrors := make(map[string]error)
	for _, d := range details {
		if d.Err != nil {
			toolErrors[d.Tool] = d.Err
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
