package trivy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Trivy — container and dependency vulnerability scanning.
// trivy fs [path] --format json --quiet
//
// Output shape:
//
//	{ "Results": [ { "Target": "requirements.txt", "Type": "pip",
//	                 "Vulnerabilities": [ { "VulnerabilityID": "CVE-...",
//	                   "Severity": "HIGH", "Title": "...",
//	                   "InstalledVersion": "1.0.0",
//	                   "FixedVersion": "1.2.0" } ] } ] }
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "trivy" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("trivy: Src path is required")
	}

	args := []string{
		"fs",
		"--format", "json",
		"--quiet",
		"--exit-code", "0", // never fail on findings
		opts.Src,
	}
	if extra, ok := opts.ExtraArgs["trivy"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "trivy", args...)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string      `json:"Target"`
	Type            string      `json:"Type"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	CweIDs           []string `json:"CweIDs"`
	References       []string `json:"References"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out trivyOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("trivy: parse JSON: %w", err)
	}

	var findings []scanner.Finding
	for _, r := range out.Results {
		for _, v := range r.Vulnerabilities {
			msg := v.Title
			if msg == "" {
				msg = v.Description
			}

			cwe := v.VulnerabilityID // CVE ID
			if len(v.CweIDs) > 0 {
				cwe = v.CweIDs[0]
			}

			fixSignal := ""
			if v.FixedVersion != "" {
				fixSignal = "upgrade to " + v.FixedVersion
			}

			findings = append(findings, scanner.Finding{
				Tool:      "trivy",
				Severity:  scanner.NormaliseSeverity(v.Severity),
				RuleID:    v.VulnerabilityID,
				Message:   msg,
				Path:      r.Target,
				CWE:       cwe,
				FixSignal: fixSignal,
				Raw: map[string]any{
					"pkg_name":          v.PkgName,
					"installed_version": v.InstalledVersion,
					"target_type":       r.Type,
					"references":        v.References,
				},
			})
		}
	}
	return findings, nil
}
