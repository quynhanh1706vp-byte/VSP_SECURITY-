package semgrep

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Semgrep — rule-based SAST.
// We use --json output (simpler than SARIF for semgrep's format).
//
// Output shape:
//
//	{ "results": [ { "check_id": "...", "path": "...", "start": {"line": 1},
//	                 "extra": { "severity": "ERROR", "message": "...",
//	                            "metadata": {"cwe": ["CWE-79"]} } } ] }
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "semgrep" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("semgrep: Src path is required")
	}

	args := []string{
		"scan",
		"--json",
		"--quiet",
		"--config=auto", // use community rules; override with ExtraArgs
		opts.Src,
	}
	if extra, ok := opts.ExtraArgs["semgrep"]; ok {
		// Allow caller to replace --config=auto with custom ruleset
		args = append(args[:len(args)-2], extra...) // splice before src
		args = append(args, opts.Src)
	}

	res, err := scanner.Run(ctx, "semgrep", args...)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
}

type semgrepExtra struct {
	Severity string          `json:"severity"`
	Message  string          `json:"message"`
	Metadata semgrepMetadata `json:"metadata"`
	Fix      string          `json:"fix"`
}

type semgrepMetadata struct {
	CWE        []string `json:"cwe"`
	Confidence string   `json:"confidence"`
	References []string `json:"references"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out semgrepOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("semgrep: parse JSON: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(out.Results))
	for _, r := range out.Results {
		cwe := ""
		if len(r.Extra.Metadata.CWE) > 0 {
			cwe = r.Extra.Metadata.CWE[0]
		}

		findings = append(findings, scanner.Finding{
			Tool:      "semgrep",
			Severity:  scanner.NormaliseSeverity(r.Extra.Severity),
			RuleID:    r.CheckID,
			Message:   r.Extra.Message,
			Path:      r.Path,
			Line:      r.Start.Line,
			CWE:       cwe,
			FixSignal: r.Extra.Fix,
			Raw: map[string]any{
				"confidence": r.Extra.Metadata.Confidence,
				"references": r.Extra.Metadata.References,
			},
		})
	}
	return findings, nil
}
