package hadolint

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}

func New() *Adapter      { return &Adapter{} }
func (a *Adapter) Name() string { return "hadolint" }

// Run scans Dockerfiles in opts.Src using hadolint.
// Requires hadolint binary on PATH.
func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, nil
	}

	// Find all Dockerfiles under src
	var dockerfiles []string
	err := filepath.WalkDir(opts.Src, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() { return nil }
		name := strings.ToLower(d.Name())
		if name == "dockerfile" || strings.HasPrefix(name, "dockerfile.") {
			dockerfiles = append(dockerfiles, path)
		}
		return nil
	})
	if err != nil || len(dockerfiles) == 0 {
		return nil, nil
	}

	var allFindings []scanner.Finding
	for _, df := range dockerfiles {
		findings, err := scanDockerfile(ctx, df)
		if err != nil {
			continue // tool not found or parse error — non-fatal
		}
		allFindings = append(allFindings, findings...)
	}
	return allFindings, nil
}

func scanDockerfile(ctx context.Context, path string) ([]scanner.Finding, error) {
	res, err := scanner.Run(ctx, "hadolint",
		"--format", "json",
		"--no-fail", // exit 0 even if findings present
		path)
	if err != nil {
		return nil, fmt.Errorf("hadolint: %w", err)
	}
	if len(bytes.TrimSpace(res.Stdout)) == 0 {
		return nil, nil
	}
	return parseJSON(res.Stdout, path)
}

type hadolintResult struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Level   string `json:"level"`   // error | warning | info | style
	Code    string `json:"code"`    // DL3002, SC2086, etc.
	Message string `json:"message"`
	File    string `json:"file"`
}

func parseJSON(data []byte, defaultFile string) ([]scanner.Finding, error) {
	// hadolint outputs JSON array
	var results []hadolintResult
	if err := json.Unmarshal(data, &results); err != nil {
		// fallback: try line-by-line (some versions output NDJSON)
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			var r hadolintResult
			if json.Unmarshal(sc.Bytes(), &r) == nil {
				results = append(results, r)
			}
		}
	}

	var findings []scanner.Finding
	for _, r := range results {
		sev := levelToSeverity(r.Level)
		if sev == scanner.SevInfo || sev == scanner.SevTrace { continue } // skip style
		file := r.File
		if file == "" { file = defaultFile }
		findings = append(findings, scanner.Finding{
			Tool:      "hadolint",
			Severity:  sev,
			RuleID:    r.Code,
			Message:   r.Message,
			Path:      file,
			Line:      r.Line,
			CWE:       codeToRef(r.Code),
			FixSignal: "https://github.com/hadolint/hadolint/wiki/" + r.Code,
			Category:  scanner.SourceIAC,
		})
	}
	return findings, nil
}

func levelToSeverity(level string) scanner.Severity {
	switch strings.ToLower(level) {
	case "error":
		return scanner.SevHigh
	case "warning":
		return scanner.SevMedium
	case "info":
		return scanner.SevLow
	default:
		return scanner.SevInfo // style → skip
	}
}

// codeToRef maps hadolint rule codes to CIS/NIST references
func codeToRef(code string) string {
	refs := map[string]string{
		"DL3001": "CIS-DI-0001", // apt-get upgrade
		"DL3002": "CIS-DI-0006", // last USER should not be root
		"DL3003": "CIS-DI-0001", // use WORKDIR instead of cd
		"DL3006": "CIS-DI-0001", // always tag image version
		"DL3007": "CIS-DI-0001", // do not use :latest
		"DL3008": "CIS-DI-0001", // pin apt-get versions
		"DL3009": "CIS-DI-0001", // delete apt lists
		"DL3020": "CIS-DI-0010", // use COPY not ADD
		"DL3025": "CIS-DI-0001", // use JSON for CMD/ENTRYPOINT
		"DL4006": "CIS-DI-0001", // set SHELL option -o pipefail
	}
	if ref, ok := refs[code]; ok { return ref }
	return "CIS-Docker-Benchmark"
}
