package checkov

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}
func New() *Adapter { return &Adapter{} }
func (a *Adapter) Name() string { return "checkov" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" { return nil, fmt.Errorf("checkov: Src required") }
	args := []string{"-d", opts.Src, "-o", "json", "--quiet", "--compact"}
	if extra, ok := opts.ExtraArgs["checkov"]; ok { args = append(args, extra...) }
	res, err := scanner.Run(ctx, "checkov", args...)
	if err != nil { return nil, err }
	if len(res.Stdout) == 0 { return nil, nil }
	return parse(res.Stdout)
}

type checkovOutput struct {
	Results struct {
		FailedChecks []checkovCheck `json:"failed_checks"`
	} `json:"results"`
}
type checkovCheck struct {
	CheckID   string `json:"check_id"`
	CheckName string `json:"check_name"`
	Severity  string `json:"severity"`
	Resource  string `json:"resource"`
	File      string `json:"file_path"`
	Line      []int  `json:"file_line_range"`
	Guideline string `json:"guideline"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out checkovOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("checkov: JSON: %w", err)
	}
	var findings []scanner.Finding
	for _, c := range out.Results.FailedChecks {
		line := 0
		if len(c.Line) > 0 { line = c.Line[0] }
		findings = append(findings, scanner.Finding{
			Tool:      "checkov",
			Severity:  scanner.NormaliseSeverity(c.Severity),
			RuleID:    c.CheckID,
			Message:   c.CheckName,
			Path:      c.File,
			Line:      line,
			FixSignal: c.Guideline,
			Raw:       map[string]any{"resource": c.Resource},
		})
	}
	return findings, nil
}
