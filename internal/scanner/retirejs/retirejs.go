package retirejs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs retire.js — detects outdated/vulnerable JavaScript libraries.
//
// retire.js scans JS files (both standalone and bundled in HTML) and matches
// them against a database of known-vulnerable versions. Very useful for web
// frontends that include CDN libraries (jQuery, Bootstrap, Lodash, etc.).
//
// Output (retire --outputformat json):
//
//	{ "version": "5.4.2", "data": [
//	    { "file": "app.min.js", "results": [
//	        { "component": "jquery", "version": "1.6.1",
//	          "vulnerabilities": [
//	            { "severity": "medium", "identifiers": {"CVE": ["CVE-..."]},
//	              "info": ["..."], "summary": "..." } ] } ] } ] }
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "retire-js" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("retire-js: Src path is required")
	}

	args := []string{
		"--path", opts.Src,
		"--outputformat", "json",
		"--exitwith", "0", // don't exit non-zero on findings
	}
	if extra, ok := opts.ExtraArgs["retire-js"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "retire", args...)
	if err != nil && len(res.Stdout) == 0 {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type retireOutput struct {
	Version string       `json:"version"`
	Data    []retireFile `json:"data"`
}

type retireFile struct {
	File    string           `json:"file"`
	Results []retireResult   `json:"results"`
}

type retireResult struct {
	Component       string            `json:"component"`
	Version         string            `json:"version"`
	Vulnerabilities []retireVulnInfo  `json:"vulnerabilities"`
}

type retireVulnInfo struct {
	Severity    string            `json:"severity"`
	Identifiers retireIdentifiers `json:"identifiers"`
	Info        []string          `json:"info"`
	Summary     string            `json:"summary"`
}

type retireIdentifiers struct {
	CVE     []string `json:"CVE"`
	Summary string   `json:"summary"`
	Issue   string   `json:"issue"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out retireOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("retire-js: parse JSON: %w", err)
	}

	var findings []scanner.Finding
	for _, f := range out.Data {
		for _, r := range f.Results {
			for _, v := range r.Vulnerabilities {
				cwe := ""
				if len(v.Identifiers.CVE) > 0 {
					cwe = v.Identifiers.CVE[0]
				}

				summary := v.Summary
				if summary == "" && v.Identifiers.Summary != "" {
					summary = v.Identifiers.Summary
				}
				msg := fmt.Sprintf("%s@%s: %s", r.Component, r.Version, summary)
				if summary == "" {
					msg = fmt.Sprintf("%s@%s (vulnerable)", r.Component, r.Version)
				}

				info := ""
				if len(v.Info) > 0 {
					info = v.Info[0]
				}

				findings = append(findings, scanner.Finding{
					Tool:      "retire-js",
					Severity:  mapSeverity(v.Severity),
					RuleID:    fmt.Sprintf("%s:%s", r.Component, r.Version),
					Message:   msg,
					Path:      f.File,
					Line:      0,
					CWE:       cwe,
					FixSignal: "Update " + r.Component + " to a patched version",
					Raw: map[string]any{
						"component": r.Component,
						"version":   r.Version,
						"cves":      v.Identifiers.CVE,
						"info":      info,
					},
					Category: scanner.SourceSCA,
				})
			}
		}
	}
	return findings, nil
}

func mapSeverity(s string) scanner.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return scanner.SevCritical
	case "high":
		return scanner.SevHigh
	case "medium":
		return scanner.SevMedium
	case "low":
		return scanner.SevLow
	default:
		return scanner.SevMedium
	}
}
