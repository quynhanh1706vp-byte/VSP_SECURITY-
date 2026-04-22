package gosec

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs gosec — Golang security checker.
// gosec outputs JSON with this shape:
//
//	{ "Issues": [ { "severity": "MEDIUM", "confidence": "HIGH",
//	               "cwe": {"id": "22", "url": "..."},
//	               "rule_id": "G304", "details": "...",
//	               "file": "...", "line": "84", "column": "14",
//	               "autofix": "..." } ],
//	  "Stats": {...}, "GosecVersion": "..." }
//
// Note: gosec returns line/column/cwe.id as STRINGS (unlike bandit which
// uses ints). Parser handles both empty/non-numeric values safely.
//
// Exit codes: 0 = no issues, 1 = issues found (not an error for us).
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "gosec" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("gosec: Src path is required")
	}

	// gosec needs "./..." pattern to recursively scan Go packages.
	target := opts.Src
	if len(target) < 4 || target[len(target)-4:] != "/..." {
		target = target + "/..."
	}

	args := []string{
		"-fmt=json",
		"-quiet",            // suppress scanning progress to stderr only
		"-no-fail",          // exit 0 even when findings exist (cleaner for CI)
		"-severity=low",     // report all severities; pipeline filters later
		"-confidence=low",
		target,
	}
	if extra, ok := opts.ExtraArgs["gosec"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "gosec", args...)
	if err != nil {
		return nil, err
	}

	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type gosecOutput struct {
	Issues       []gosecIssue   `json:"Issues"`
	Stats        gosecStats     `json:"Stats"`
	GosecVersion string         `json:"GosecVersion"`
	GolangErrors map[string]any `json:"Golang errors"`
}

type gosecIssue struct {
	Severity     string   `json:"severity"`
	Confidence   string   `json:"confidence"`
	CWE          gosecCWE `json:"cwe"`
	RuleID       string   `json:"rule_id"`
	Details      string   `json:"details"`
	File         string   `json:"file"`
	Code         string   `json:"code"`
	Line         string   `json:"line"`
	Column       string   `json:"column"`
	NoSec        bool     `json:"nosec"`
	Autofix      string   `json:"autofix"`
	Suppressions []any    `json:"suppressions"`
}

type gosecCWE struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type gosecStats struct {
	Files int `json:"files"`
	Lines int `json:"lines"`
	Nosec int `json:"nosec"`
	Found int `json:"found"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out gosecOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("gosec: parse JSON: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(out.Issues))
	for _, iss := range out.Issues {
		cwe := ""
		if iss.CWE.ID != "" {
			cwe = "CWE-" + iss.CWE.ID
		}

		// gosec returns line as string, may be a single number or range "84-85"
		line := 0
		if iss.Line != "" {
			if n, err := strconv.Atoi(iss.Line); err == nil {
				line = n
			}
		}

		findings = append(findings, scanner.Finding{
			Tool:      "gosec",
			Severity:  scanner.NormaliseSeverity(iss.Severity),
			RuleID:    iss.RuleID,
			Message:   iss.Details,
			Path:      iss.File,
			Line:      line,
			CWE:       cwe,
			FixSignal: iss.Autofix,
			Raw: map[string]any{
				"confidence": iss.Confidence,
				"column":     iss.Column,
				"code":       iss.Code,
				"cwe_url":    iss.CWE.URL,
			},
		})
	}
	return findings, nil
}
