package osvscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs osv-scanner — Google's vulnerability scanner.
//
// OSV-Scanner queries the OSV.dev database (aggregated from GitHub Advisory,
// PyPI, npm, Go vuln DB, RustSec, OSS-Fuzz, etc.) and finds dependencies
// with known vulnerabilities.
//
// Output (osv-scanner --format json --recursive $Src):
//
//	{ "results": [
//	    { "source": { "path": "go.mod", "type": "lockfile" },
//	      "packages": [
//	        { "package": { "name": "...", "version": "...", "ecosystem": "Go" },
//	          "vulnerabilities": [
//	            { "id": "GHSA-xxx", "summary": "...", "severity": [...],
//	              "database_specific": { "severity": "HIGH" } } ] } ] }
//	]}
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "osv-scanner" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("osv-scanner: Src path is required")
	}

	args := []string{
		"--format", "json",
		"--recursive",
		opts.Src,
	}
	if extra, ok := opts.ExtraArgs["osv-scanner"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "osv-scanner", args...)
	// osv-scanner exits 1 when vulns found — stdout still valid JSON.
	// We inspect stdout regardless.
	if err != nil && len(res.Stdout) == 0 {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type osvOutput struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource   `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvPackage struct {
	Package         osvPkgInfo         `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
	Groups          []osvGroup         `json:"groups"`
}

type osvPkgInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVulnerability struct {
	ID               string              `json:"id"`
	Summary          string              `json:"summary"`
	Details          string              `json:"details"`
	Aliases          []string            `json:"aliases"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
	Severity         []osvSeverity       `json:"severity"`
}

type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`  // e.g. "CVSS_V3"
	Score string `json:"score"` // e.g. "CVSS:3.1/AV:N/..."
}

type osvGroup struct {
	IDs         []string `json:"ids"`
	MaxSeverity string   `json:"max_severity"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out osvOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("osv-scanner: parse JSON: %w", err)
	}

	var findings []scanner.Finding
	for _, r := range out.Results {
		for _, p := range r.Packages {
			for _, v := range p.Vulnerabilities {
				sev := mapSeverity(v.DatabaseSpecific.Severity)

				// Pick preferred CVE alias if present
				cwe := v.ID
				for _, a := range v.Aliases {
					if strings.HasPrefix(a, "CVE-") {
						cwe = a
						break
					}
				}

				msg := fmt.Sprintf("%s@%s: %s",
					p.Package.Name, p.Package.Version, v.Summary)
				if v.Summary == "" {
					msg = fmt.Sprintf("%s@%s (%s)",
						p.Package.Name, p.Package.Version, v.ID)
				}

				findings = append(findings, scanner.Finding{
					Tool:     "osv-scanner",
					Severity: sev,
					RuleID:   v.ID,
					Message:  msg,
					Path:     r.Source.Path,
					Line:     0,
					CWE:      cwe,
					CVSS:     0,
					Raw: map[string]any{
						"ecosystem": p.Package.Ecosystem,
						"package":   p.Package.Name,
						"version":   p.Package.Version,
						"aliases":   v.Aliases,
						"source":    r.Source.Type,
					},
					Category: scanner.SourceSCA,
				})
			}
		}
	}
	return findings, nil
}

func mapSeverity(s string) scanner.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return scanner.SevCritical
	case "HIGH":
		return scanner.SevHigh
	case "MODERATE", "MEDIUM":
		return scanner.SevMedium
	case "LOW":
		return scanner.SevLow
	default:
		return scanner.SevMedium // OSV often omits severity; default medium
	}
}
