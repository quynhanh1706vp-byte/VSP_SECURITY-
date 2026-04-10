package gitleaks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Gitleaks — git history secret and credential scanning.
// gitleaks detect --source [path] --report-format json --report-path /dev/stdout
//
// Output: JSON array of leak objects
//
//	[ { "Description": "...", "StartLine": 10, "File": "...",
//	    "RuleID": "aws-access-token", "Secret": "AKI...",
//	    "Match": "...", "Author": "...", "Date": "..." } ]
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "gitleaks" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("gitleaks: Src path is required")
	}

	args := []string{
		"detect",
		"--source", opts.Src,
		"--report-format", "json",
		"--report-path", "/dev/stdout",
		"--no-git", // scan files directly, not git history
		"--exit-code", "0",
	}
	if extra, ok := opts.ExtraArgs["gitleaks"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "gitleaks", args...)
	if err != nil {
		return nil, err
	}

	// gitleaks exits 1 when leaks found — stdout contains JSON
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type gitleaksLeak struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	File        string   `json:"File"`
	RuleID      string   `json:"RuleID"`
	Tags        []string `json:"Tags"`
	Match       string   `json:"Match"` // masked by gitleaks
	Commit      string   `json:"Commit"`
	Author      string   `json:"Author"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var leaks []gitleaksLeak
	if err := json.Unmarshal(data, &leaks); err != nil {
		return nil, fmt.Errorf("gitleaks: parse JSON: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(leaks))
	for _, l := range leaks {
		findings = append(findings, scanner.Finding{
			Tool:      "gitleaks",
			Severity:  scanner.SevCritical, // secrets are always CRITICAL
			RuleID:    l.RuleID,
			Message:   l.Description,
			Path:      l.File,
			Line:      l.StartLine,
			CWE:       "CWE-798", // hard-coded credentials
			FixSignal: "rotate secret immediately, then remove from repo history",
			Raw: map[string]any{
				"match":  l.Match, // already masked by gitleaks
				"commit": l.Commit,
				"author": l.Author,
				"tags":   l.Tags,
			},
		})
	}
	return findings, nil
}
