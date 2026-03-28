package bandit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Bandit — Python SAST tool.
// Bandit outputs JSON with this shape:
//
//	{ "results": [ { "issue_severity": "HIGH", "issue_text": "...",
//	                 "filename": "...", "line_number": 1,
//	                 "test_id": "B101", "issue_cwe": {"id": 78} } ] }
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "bandit" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("bandit: Src path is required")
	}

	args := []string{
		"-r", opts.Src,
		"-f", "json",
		"-q", // quiet — suppress progress output
	}
	if extra, ok := opts.ExtraArgs["bandit"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "bandit", args...)
	if err != nil {
		return nil, err
	}

	// bandit exits 1 when findings exist — not an error for us
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type banditOutput struct {
	Results []banditResult `json:"results"`
}

type banditResult struct {
	TestID        string    `json:"test_id"`
	TestName      string    `json:"test_name"`
	IssueSeverity string    `json:"issue_severity"`
	IssueText     string    `json:"issue_text"`
	Filename      string    `json:"filename"`
	LineNumber    int       `json:"line_number"`
	IssueCWE      banditCWE `json:"issue_cwe"`
	MoreInfo      string    `json:"more_info"`
	Code          string    `json:"code"`
}

type banditCWE struct {
	ID   int    `json:"id"`
	Link string `json:"link"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out banditOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("bandit: parse JSON: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(out.Results))
	for _, r := range out.Results {
		cwe := ""
		if r.IssueCWE.ID > 0 {
			cwe = fmt.Sprintf("CWE-%d", r.IssueCWE.ID)
		}

		findings = append(findings, scanner.Finding{
			Tool:      "bandit",
			Severity:  scanner.NormaliseSeverity(r.IssueSeverity),
			RuleID:    r.TestID,
			Message:   r.IssueText,
			Path:      r.Filename,
			Line:      r.LineNumber,
			CWE:       cwe,
			FixSignal: r.MoreInfo,
			Raw: map[string]any{
				"test_name": r.TestName,
				"code":      r.Code,
			},
		})
	}
	return findings, nil
}
