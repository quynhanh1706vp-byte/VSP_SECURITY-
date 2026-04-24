package govulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs govulncheck — Go's official vulnerability scanner from
// golang.org/x/vuln, checking dependencies against the Go vulnerability
// database (https://pkg.go.dev/vuln/).
//
// Only reports vulns that are ACTUALLY REACHABLE from user code — much
// lower false-positive rate than grype/trivy for Go modules.
//
// Output: newline-delimited JSON "messages" when run with -json:
//
//	{"osv": { "id": "GO-2024-1234", "aliases":["CVE-..."], "summary":"..." }}
//	{"finding": { "osv":"GO-2024-1234", "trace":[{"module":"...","package":"..."}] }}
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "govulncheck" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("govulncheck: Src path is required")
	}

	args := []string{
		"-C", opts.Src, // working directory
		"-format", "json",
		"./...",
	}
	if extra, ok := opts.ExtraArgs["govulncheck"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "govulncheck", args...)
	// govulncheck exits non-zero when vulns are found — not a hard error
	if err != nil && len(res.Stdout) == 0 {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}
	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

// message is the top-level wrapper for each JSON line in govulncheck -json output.
type message struct {
	OSV     *osvEntry `json:"osv,omitempty"`
	Finding *osvFind  `json:"finding,omitempty"`
}

type osvEntry struct {
	ID      string   `json:"id"`      // e.g. "GO-2024-1234"
	Aliases []string `json:"aliases"` // often contains CVE-xxxx-xxxx
	Summary string   `json:"summary"`
	Details string   `json:"details"`
}

type osvFind struct {
	OSV          string      `json:"osv"` // references osvEntry.ID
	FixedVersion string      `json:"fixed_version"`
	Trace        []traceElem `json:"trace"`
}

type traceElem struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	// govulncheck emits newline-delimited JSON; not a single JSON array.
	dec := json.NewDecoder(strings.NewReader(string(data)))

	// Pass 1: index all OSV entries by ID
	osvByID := make(map[string]*osvEntry)
	var findings []*osvFind

	for dec.More() {
		var m message
		if err := dec.Decode(&m); err != nil {
			// tolerate trailing garbage; bail only on first-token errors
			if len(osvByID) == 0 && len(findings) == 0 {
				return nil, fmt.Errorf("govulncheck: parse json: %w", err)
			}
			break
		}
		if m.OSV != nil {
			osvByID[m.OSV.ID] = m.OSV
		}
		if m.Finding != nil {
			findings = append(findings, m.Finding)
		}
	}

	// Pass 2: materialise findings with OSV metadata
	out := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		osv := osvByID[f.OSV]

		// Extract module + package from first trace element
		var mod, pkg string
		if len(f.Trace) > 0 {
			mod = f.Trace[0].Module
			pkg = f.Trace[0].Package
		}

		// Prefer CVE alias for CWE field; fallback to OSV ID
		cve := f.OSV
		if osv != nil {
			for _, a := range osv.Aliases {
				if strings.HasPrefix(a, "CVE-") {
					cve = a
					break
				}
			}
		}

		msg := fmt.Sprintf("Reachable Go vuln in %s", pkg)
		if osv != nil && osv.Summary != "" {
			msg = osv.Summary
		}

		fixSig := ""
		if f.FixedVersion != "" {
			fixSig = fmt.Sprintf("upgrade %s to %s", mod, f.FixedVersion)
		}

		out = append(out, scanner.Finding{
			Tool:      "govulncheck",
			Severity:  scanner.SevHigh, // reachable = exploitable → HIGH by default
			RuleID:    f.OSV,
			Message:   msg,
			Path:      pkg,
			Line:      0,
			CWE:       cve,
			FixSignal: fixSig,
			Raw: map[string]any{
				"osv_id":        f.OSV,
				"module":        mod,
				"package":       pkg,
				"fixed_version": f.FixedVersion,
				"trace_depth":   len(f.Trace),
			},
			Category: scanner.SourceSCA,
		})
	}

	return out, nil
}
