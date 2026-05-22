package gofuzz

import (
	"context"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter wraps gofuzz.Run to implement scanner.Runner interface.
// Runs `go test -fuzz` for each FuzzXxx function in opts.Src.
type Adapter struct {
	PerTargetDuration string // default 30s
}

func NewAdapter() *Adapter { return &Adapter{PerTargetDuration: "30s"} }

func (a *Adapter) Name() string { return "gofuzz" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, nil
	}

	dur := a.PerTargetDuration
	if dur == "" {
		dur = "30s"
	}

	raw, err := Run(ctx, opts.Src, dur)
	if err != nil {
		return nil, fmt.Errorf("gofuzz: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(raw))
	for _, f := range raw {
		findings = append(findings, scanner.Finding{
			Tool:     "gofuzz",
			Severity: scanner.NormaliseSeverity(f.Severity),
			RuleID:   f.FuzzFunc,
			Message:  f.Title,
			Path:     f.Package,
			Raw: map[string]any{
				"crash":   f.Crash,
				"details": f.Details,
			},
		})
	}
	return findings, nil
}
