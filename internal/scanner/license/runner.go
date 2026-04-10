package license

import (
	"context"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

type Runner struct{ s *Scanner }

func NewRunner() *Runner       { return &Runner{s: NewScanner(DefaultPolicy)} }
func (r *Runner) Name() string { return "license" }

func (r *Runner) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("license: Src required")
	}
	result, err := r.s.Scan(opts.Src)
	if err != nil {
		return nil, fmt.Errorf("license: scan failed: %w", err)
	}
	var findings []scanner.Finding
	for _, c := range result.Components {
		var sev scanner.Severity
		switch c.RiskLevel {
		case "CRITICAL":
			sev = scanner.SevCritical // GPL/AGPL — forbidden
		case "MEDIUM":
			sev = scanner.SevMedium // LGPL — restricted
		default:
			continue // allowed/unknown → skip
		}
		findings = append(findings, scanner.Finding{
			Tool:      "license",
			Severity:  sev,
			RuleID:    fmt.Sprintf("license-%s", c.License),
			Message:   fmt.Sprintf("Dependency %s@%s uses %s license (%s)", c.Name, c.Version, c.License, c.PolicyStatus),
			Path:      "go.mod",
			CWE:       "CWE-1104", // use of unmaintained/non-compliant third-party component
			FixSignal: fmt.Sprintf("Replace or vendor %s — %s license is %s under NTIA/DoD policy", c.Name, c.License, c.PolicyStatus),
			Raw: map[string]any{
				"name":           c.Name,
				"version":        c.Version,
				"license":        c.License,
				"policy_status":  c.PolicyStatus,
				"ntia_compliant": c.NTIACompliant,
				"type":           c.Type,
			},
		})
	}
	return findings, nil
}
