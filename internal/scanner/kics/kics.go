package kics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}

func New() *Adapter      { return &Adapter{} }
func (a *Adapter) Name() string { return "kics" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("kics: Src required")
	}
	// Check if kics is available
	if _, err := exec.LookPath("kics"); err != nil {
		return nil, fmt.Errorf("tool not found on PATH: kics")
	}

	outDir, err := os.MkdirTemp("", "kics_out_*")
	if err != nil {
		return nil, fmt.Errorf("kics: mktemp: %w", err)
	}
	defer os.RemoveAll(outDir)

	args := []string{
		"scan",
		"-p", opts.Src,
		"--report-formats", "json",
		"--output-path", outDir,
		"--output-name", "results",
		"--no-progress",
		"--silent",
		"--fail-on", "none",
	}
	if extra, ok := opts.ExtraArgs["kics"]; ok {
		args = append(args, extra...)
	}

	if _, err := scanner.Run(ctx, "kics", args...); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Join(outDir, "results.json"))
	if err != nil {
		return nil, nil // no IaC files found = 0 findings
	}
	return parse(data)
}

type kicsOutput struct {
	Queries []kicsQuery `json:"queries"`
}

type kicsQuery struct {
	QueryName string     `json:"query_name"`
	QueryID   string     `json:"query_id"`
	Severity  string     `json:"severity"`
	Platform  string     `json:"platform"`
	Files     []kicsFile `json:"files"`
}

type kicsFile struct {
	FileName  string `json:"file_name"`
	Line      int    `json:"line"`
	IssueType string `json:"issue_type"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out kicsOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("kics: JSON: %w", err)
	}
	var findings []scanner.Finding
	for _, q := range out.Queries {
		for _, f := range q.Files {
			findings = append(findings, scanner.Finding{
				Tool:      "kics",
				Severity:  scanner.NormaliseSeverity(q.Severity),
				RuleID:    q.QueryID,
				Message:   q.QueryName,
				Path:      f.FileName,
				Line:      f.Line,
				FixSignal: "kics: " + q.QueryName,
				Raw: map[string]any{
					"platform":   q.Platform,
					"issue_type": f.IssueType,
				},
			})
		}
	}
	return findings, nil
}
