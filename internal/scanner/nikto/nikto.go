package nikto

import (
	"context"
	"encoding/xml"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}

func New() *Adapter      { return &Adapter{} }
func (a *Adapter) Name() string { return "nikto" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	target := opts.URL
	if target == "" {
		target = opts.Src
	}
	if target == "" {
		return nil, fmt.Errorf("nikto: URL required for DAST")
	}

	maxTime := 90
	if opts.TimeoutSec > 0 && opts.TimeoutSec < maxTime {
		maxTime = opts.TimeoutSec
	}

	args := []string{
		"-h", target,
		"-Format", "xml",
		"-o", "/dev/stdout",
		"-nointeractive",
		"-maxtime", fmt.Sprintf("%ds", maxTime),
		"-timeout", "10",
	}
	if extra, ok := opts.ExtraArgs["nikto"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "nikto", args...)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}
	return parseXML(res.Stdout)
}

type niktoScan struct {
	XMLName     xml.Name       `xml:"niktoscan"`
	ScanDetails []niktoDetails `xml:"scandetails"`
}

type niktoDetails struct {
	TargetIP   string      `xml:"targetip,attr"`
	TargetPort string      `xml:"targetport,attr"`
	Items      []niktoItem `xml:"item"`
}

type niktoItem struct {
	ID          string `xml:"id,attr"`
	OSVDBID     string `xml:"osvdbid,attr"`
	Method      string `xml:"method,attr"`
	Description string `xml:"description"`
	URI         string `xml:"uri"`
	NameLink    string `xml:"namelink"`
}

func parseXML(data []byte) ([]scanner.Finding, error) {
	var out niktoScan
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("nikto: parse XML: %w", err)
	}
	var findings []scanner.Finding
	for _, d := range out.ScanDetails {
		for _, item := range d.Items {
			findings = append(findings, scanner.Finding{
				Tool:      "nikto",
				Severity:  scanner.SevMedium,
				RuleID:    "NIKTO-" + item.ID,
				Message:   item.Description,
				Path:      item.URI,
				FixSignal: item.NameLink,
				Raw: map[string]any{
					"osvdb_id": item.OSVDBID,
					"method":   item.Method,
					"target":   d.TargetIP + ":" + d.TargetPort,
				},
			})
		}
	}
	return findings, nil
}
