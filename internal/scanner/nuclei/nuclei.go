package nuclei

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}

func New() *Adapter             { return &Adapter{} }
func (a *Adapter) Name() string { return "nuclei" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("nuclei: URL required")
	}
	res, err := scanner.Run(ctx, "nuclei",
		"-u", opts.URL, "-json", "-silent", "-no-color",
		"-severity", "medium,high,critical", "-timeout", "10")
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}
	var findings []scanner.Finding
	for _, line := range bytes.Split(res.Stdout, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var r struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
			MatchedAt string `json:"matched-at"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		findings = append(findings, scanner.Finding{
			Tool:      "nuclei",
			Severity:  scanner.NormaliseSeverity(r.Info.Severity),
			RuleID:    r.TemplateID,
			Message:   r.Info.Name,
			Path:      r.MatchedAt,
			FixSignal: "https://nuclei.projectdiscovery.io/templates/" + r.TemplateID,
		})
	}
	return findings, nil
}
