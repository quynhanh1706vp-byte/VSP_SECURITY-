package syft

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Syft — Software Bill of Materials (SBOM) generator.
// Produces CycloneDX JSON listing every dependency in the scan target.
//
// SBOM is mandatory under:
//   - US Executive Order 14028 (Improving the Nation's Cybersecurity)
//   - EU Cyber Resilience Act (CRA)
//   - VN Nghị định 13/2023/NĐ-CP (data protection)
//
// Syft emits one "component" per dependency. We treat each as an INFO-level
// finding tagged with the component PURL so downstream (grype, govulncheck,
// license, trivy) can correlate CVEs back to the SBOM.
//
// Output shape (abridged CycloneDX):
//
//	{ "components": [
//	    { "type": "library", "name": "pkg", "version": "1.2.3",
//	      "purl": "pkg:golang/foo@1.2.3",
//	      "licenses": [ { "license": { "id": "MIT" } } ] } ] }
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "syft" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("syft: Src path is required")
	}

	args := []string{
		"scan",
		"dir:" + opts.Src,
		"-o", "cyclonedx-json",
		"-q",
	}
	if extra, ok := opts.ExtraArgs["syft"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "syft", args...)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}
	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type cdxOutput struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type     string       `json:"type"`
	Name     string       `json:"name"`
	Version  string       `json:"version"`
	PURL     string       `json:"purl"`
	Licenses []cdxLicense `json:"licenses"`
}

type cdxLicense struct {
	License cdxLicenseInner `json:"license"`
}

type cdxLicenseInner struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out cdxOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("syft: parse cyclonedx json: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(out.Components))
	for _, c := range out.Components {
		if c.Name == "" {
			continue
		}

		// Extract license (prefer SPDX id over free-form name)
		license := "UNKNOWN"
		for _, l := range c.Licenses {
			if l.License.ID != "" {
				license = l.License.ID
				break
			}
			if l.License.Name != "" {
				license = l.License.Name
				break
			}
		}

		path := c.Name
		if c.Version != "" {
			path = c.Name + "@" + c.Version
		}

		findings = append(findings, scanner.Finding{
			Tool:     "syft",
			Severity: scanner.SevInfo, // SBOM entries are informational
			RuleID:   "SBOM-COMPONENT",
			Message:  fmt.Sprintf("Component: %s (type=%s license=%s)", path, c.Type, license),
			Path:     path,
			Line:     0,
			CWE:      "",
			Raw: map[string]any{
				"purl":    c.PURL,
				"name":    c.Name,
				"version": c.Version,
				"type":    c.Type,
				"license": license,
				"source":  "syft-cyclonedx",
			},
			Category: scanner.SourceSCA,
		})
	}
	return findings, nil
}
