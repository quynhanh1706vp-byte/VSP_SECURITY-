package grype

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Grype — vulnerability scanner against SBOM / packages.
// Output: grype [source] -o json
//
//	{ "matches": [ { "vulnerability": { "id": "CVE-...", "severity": "High",
//	                  "description": "...", "fix": { "versions": ["1.2.3"] } },
//	                "artifact": { "name": "pkg", "version": "1.0.0" } } ] }
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "grype" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	src := opts.Src
	if src == "" {
		return nil, fmt.Errorf("grype: Src path is required")
	}

	args := []string{
		src,
		"-o", "json",
		"--quiet",
		"--fail-on", "none", // never exit non-zero on findings
	}
	if extra, ok := opts.ExtraArgs["grype"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "grype", args...)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type grypeOutput struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVuln    `json:"vulnerability"`
	Artifact      grypeArtifact `json:"artifact"`
}

type grypeVuln struct {
	ID          string    `json:"id"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Fix         grypeFix  `json:"fix"`
	URLs        []string  `json:"urls"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"` // "fixed", "not-fixed", "wont-fix"
}

type grypeArtifact struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"` // "deb", "go-module", "python", …
	Location string `json:"locations"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out grypeOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("grype: parse JSON: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(out.Matches))
	for _, m := range out.Matches {
		fixSignal := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixSignal = "upgrade to " + m.Vulnerability.Fix.Versions[0]
		} else if m.Vulnerability.Fix.State != "" {
			fixSignal = m.Vulnerability.Fix.State
		}

		pkg := fmt.Sprintf("%s@%s", m.Artifact.Name, m.Artifact.Version)

		findings = append(findings, scanner.Finding{
			Tool:      "grype",
			Severity:  scanner.NormaliseSeverity(m.Vulnerability.Severity),
			RuleID:    m.Vulnerability.ID,
			Message:   m.Vulnerability.Description,
			Path:      pkg,
			CWE:       m.Vulnerability.ID, // CVE/GHSA ID as CWE field
			FixSignal: fixSignal,
			Raw: map[string]any{
				"artifact_type": m.Artifact.Type,
				"urls":          m.Vulnerability.URLs,
				"fix_state":     m.Vulnerability.Fix.State,
			},
		})
	}
	return findings, nil
}
