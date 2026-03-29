package scanner

import (
	"context"
	"fmt"
	"time"
)

// ── Severity ──────────────────────────────────────────────────────────────────

type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevInfo     Severity = "INFO"
	SevTrace    Severity = "TRACE"
)

var severityRank = map[Severity]int{
	SevCritical: 6,
	SevHigh:     5,
	SevMedium:   4,
	SevLow:      3,
	SevInfo:     2,
	SevTrace:    1,
}

func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return 0
}

// NormaliseSeverity maps arbitrary tool-specific strings to canonical Severity.
func NormaliseSeverity(raw string) Severity {
	switch raw {
	case "critical", "CRITICAL":
		return SevCritical
	case "high", "HIGH", "error", "ERROR": // semgrep "error" = HIGH
		return SevHigh
	case "medium", "MEDIUM", "warning", "WARNING", "warn", "WARN":
		return SevMedium
	case "low", "LOW", "note", "NOTE":
		return SevLow
	case "info", "INFO", "informational", "INFORMATIONAL":
		return SevInfo
	default:
		return SevTrace
	}
}

// ── Finding ───────────────────────────────────────────────────────────────────

// Finding is the canonical, tool-agnostic representation of a security finding.
// Every tool adapter MUST normalise its output into this struct.
type Finding struct {
	Tool      string            `json:"tool"`
	Severity  Severity          `json:"severity"`
	RuleID    string            `json:"rule_id"`
	Message   string            `json:"message"`
	Path      string            `json:"path"`       // file path or package name
	Line      int               `json:"line"`       // 0 = not applicable
	CWE       string            `json:"cwe"`        // e.g. "CWE-79", "CVE-2024-1234", "GHSA-xxxx"
	FixSignal string            `json:"fix_signal"` // upgrade hint or remediation note
	Raw       map[string]any    `json:"raw"`        // original tool output for audit
}

// ── RunOpts ───────────────────────────────────────────────────────────────────

// RunOpts carries the parameters for a single tool invocation.
type RunOpts struct {
	// Src is the absolute path to the source directory to scan.
	// Required for SAST, SCA, SECRETS, IAC modes.
	Src string

	// URL is the target URL for DAST scans (nikto, nuclei).
	URL string

	// TimeoutSec is the per-tool timeout. 0 means default (300s).
	TimeoutSec int

	// Mode is the scan mode hint — tools may skip themselves based on mode.
	Mode string // SAST | DAST | SCA | SECRETS | IAC | FULL

	// ExtraArgs passes additional CLI flags per tool.
	// Key = tool name (e.g. "semgrep"), Value = extra args slice.
	ExtraArgs map[string][]string
}

func (o RunOpts) timeout() time.Duration {
	if o.TimeoutSec > 0 {
		return time.Duration(o.TimeoutSec) * time.Second
	}
	return 300 * time.Second
}

// ── Runner interface ──────────────────────────────────────────────────────────


// TimeoutOrDefault returns timeout duration, defaulting to 300s.
func (o RunOpts) TimeoutOrDefault() time.Duration {
	if o.TimeoutSec > 0 {
		return time.Duration(o.TimeoutSec) * time.Second
	}
	return 300 * time.Second
}

// Runner is implemented by each tool adapter (bandit, semgrep, grype, …).
// Each adapter is responsible for:
//   1. Invoking the tool binary via exec.Command
//   2. Parsing stdout (JSON / SARIF / XML)
//   3. Returning []Finding normalised to canonical fields
//
// Adapters MUST respect ctx cancellation and the timeout in RunOpts.
type Runner interface {
	// Name returns the tool identifier used in Finding.Tool and logs.
	Name() string

	// Run executes the tool and returns findings. Returning an error does NOT
	// fail the whole pipeline — the caller records the error and continues.
	Run(ctx context.Context, opts RunOpts) ([]Finding, error)
}

// ── RunResult ─────────────────────────────────────────────────────────────────

// RunResult captures the outcome of one tool within a pipeline run.
type RunResult struct {
	Tool     string
	Findings []Finding
	Err      error
	Duration time.Duration
}

// ── RunAll ────────────────────────────────────────────────────────────────────

// RunAll executes all runners concurrently under ctx, merges findings, and
// returns per-tool errors without aborting the whole run.
//
// Each runner gets its own child context bounded by opts.timeout() so a
// slow tool cannot block the others indefinitely.
func RunAll(ctx context.Context, runners []Runner, opts RunOpts) ([]Finding, []RunResult) {
	results := make(chan RunResult, len(runners))

	for _, r := range runners {
		r := r // capture
		go func() {
			tctx, cancel := context.WithTimeout(ctx, opts.timeout())
			defer cancel()

			start := time.Now()
			findings, err := r.Run(tctx, opts)
			results <- RunResult{
				Tool:     r.Name(),
				Findings: findings,
				Err:      err,
				Duration: time.Since(start),
			}
		}()
	}

	var all []Finding
	var details []RunResult
	for range runners {
		res := <-results
		details = append(details, res)
		if res.Err == nil {
			all = append(all, res.Findings...)
		}
	}
	return all, details
}

// ── Summary ───────────────────────────────────────────────────────────────────

// Summarise counts findings by severity from a slice.
type Summary struct {
	Critical   int
	High       int
	Medium     int
	Low        int
	Info       int
	Trace      int
	HasSecrets bool // true if any gitleaks finding present
}

func Summarise(findings []Finding) Summary {
	var s Summary
	for _, f := range findings {
		switch f.Severity {
		case SevCritical:
			s.Critical++
		case SevHigh:
			s.High++
		case SevMedium:
			s.Medium++
		case SevLow:
			s.Low++
		case SevInfo:
			s.Info++
		default:
			s.Trace++
		}
		if f.Tool == "gitleaks" {
			s.HasSecrets = true
		}
	}
	return s
}

// Total returns the sum of all severity counts.
func (s Summary) Total() int {
	return s.Critical + s.High + s.Medium + s.Low + s.Info + s.Trace
}

// ── ErrToolNotFound ───────────────────────────────────────────────────────────

// ErrToolNotFound is returned when the tool binary is not on PATH.
type ErrToolNotFound struct{ Tool string }

func (e ErrToolNotFound) Error() string {
	return fmt.Sprintf("tool not found on PATH: %s", e.Tool)
}
