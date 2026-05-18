package racedetect

import (
	"context"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter wraps racedetect.Run to implement scanner.Runner interface.
// Executes `go test -race ./...` and parses race condition reports.
type Adapter struct{}

func NewAdapter() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "racedetect" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, nil
	}

	raw, err := Run(ctx, opts.Src)
	if err != nil {
		return nil, fmt.Errorf("racedetect: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(raw))
	for _, f := range raw {
		findings = append(findings, scanner.Finding{
			Tool:     "racedetect",
			Severity: scanner.NormaliseSeverity(f.Severity),
			RuleID:   "data-race",
			Message:  f.Title,
			Path:     f.File,
			Line:     f.Line,
			CWE:      "CWE-362",
			Raw: map[string]any{
				"goroutine": f.Goroutine,
				"details":   f.Details,
			},
		})
	}
	return findings, nil
}
