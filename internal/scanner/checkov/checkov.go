package checkov

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}

func New() *Adapter             { return &Adapter{} }
func (a *Adapter) Name() string { return "checkov" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("checkov: Src required")
	}
	args := []string{"-d", opts.Src, "-o", "json", "--quiet", "--compact"}
	if extra, ok := opts.ExtraArgs["checkov"]; ok {
		args = append(args, extra...)
	}
	res, err := scanner.Run(ctx, "checkov", args...)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}
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

// checkovSeverity maps check_id prefix to severity since checkov
// community version does not populate the severity field.
func checkovSeverity(checkID, raw string) scanner.Severity {
	if raw != "" && raw != "None" && raw != "null" {
		return scanner.NormaliseSeverity(raw)
	}
	// Fallback: CKV_AWS / CKV2_AWS → HIGH, CKV_K8S → MEDIUM, others → LOW
	switch {
	case len(checkID) > 7 && (checkID[:7] == "CKV_AWS" || checkID[:8] == "CKV2_AWS"):
		return scanner.SevHigh
	case len(checkID) > 7 && checkID[:7] == "CKV_K8S":
		return scanner.SevMedium
	case len(checkID) > 8 && checkID[:8] == "CKV_AZUR":
		return scanner.SevHigh
	case len(checkID) > 7 && checkID[:7] == "CKV_GCP":
		return scanner.SevHigh
	default:
		return scanner.SevMedium
	}
}

func parse(data []byte) ([]scanner.Finding, error) {
	// checkov may return a single object or an array of objects (multi-type scan)
	var outputs []checkovOutput
	if data[0] == '[' {
		if err := json.Unmarshal(data, &outputs); err != nil {
			return nil, fmt.Errorf("checkov: JSON: %w", err)
		}
	} else {
		var single checkovOutput
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, fmt.Errorf("checkov: JSON: %w", err)
		}
		outputs = append(outputs, single)
	}
	var findings []scanner.Finding
	for _, out := range outputs {
		for _, c := range out.Results.FailedChecks {
			line := 0
			if len(c.Line) > 0 {
				line = c.Line[0]
			}
			findings = append(findings, scanner.Finding{
				Tool:      "checkov",
				Severity:  checkovSeverity(c.CheckID, c.Severity),
				RuleID:    c.CheckID,
				Message:   c.CheckName,
				Path:      c.File,
				Line:      line,
				FixSignal: c.Guideline,
				Raw:       map[string]any{"resource": c.Resource, "check_id": c.CheckID},
			})
		}
	}
	return findings, nil
}
