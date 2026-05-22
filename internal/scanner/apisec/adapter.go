package apisec

import (
	"context"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter wraps apisec.Scanner to implement scanner.Runner interface.
// Skips silently when no URL provided (apisec needs target URL).
type Adapter struct{}

func NewAdapter() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "apisec" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.URL == "" {
		// No target URL → skip gracefully (FULL mode often runs without URL)
		return nil, nil
	}
	s := New(opts.URL)

	// Default endpoint set covering OWASP API Top 10 hot spots
	endpoints := []string{"/api/", "/api/v1/", "/api/users/", "/api/orders/",
		"/api/admin/", "/api/internal/", "/api/v0/", "/api/test/"}

	raw, err := s.Run(ctx, endpoints)
	if err != nil {
		return nil, fmt.Errorf("apisec: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(raw))
	for _, f := range raw {
		findings = append(findings, scanner.Finding{
			Tool:     "apisec",
			Severity: scanner.NormaliseSeverity(f.Severity),
			RuleID:   string(f.Category),
			Message:  f.Title,
			Path:     f.URL,
			CWE:      "",
			Raw: map[string]any{
				"method":   f.Method,
				"details":  f.Details,
				"evidence": f.Evidence,
			},
		})
	}
	return findings, nil
}
