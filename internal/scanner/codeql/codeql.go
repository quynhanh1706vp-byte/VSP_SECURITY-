package codeql

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}
func New() *Adapter { return &Adapter{} }
func (a *Adapter) Name() string { return "codeql" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" { return nil, fmt.Errorf("codeql: Src required") }

	// Detect language from source files
	lang := detectLang(opts.Src)
	if lang == "" { return nil, nil } // no supported files found

	dbDir, err := os.MkdirTemp("", "codeql_db_*")
	if err != nil { return nil, err }
	defer os.RemoveAll(dbDir)

	resDir, err := os.MkdirTemp("", "codeql_res_*")
	if err != nil { return nil, err }
	defer os.RemoveAll(resDir)

	// Create database
	_, err = scanner.Run(ctx, "codeql", "database", "create",
		"--language="+lang,
		"--source-root="+opts.Src,
		"--overwrite",
		dbDir,
	)
	if err != nil { return nil, fmt.Errorf("codeql: database create: %w", err) }

	resFile := filepath.Join(resDir, "results.sarif")
	// Analyze
	_, err = scanner.Run(ctx, "codeql", "database", "analyze",
		dbDir,
		"--format=sarif-latest",
		"--output="+resFile,
		"--sarif-add-snippets",
	)
	if err != nil { return nil, fmt.Errorf("codeql: analyze: %w", err) }

	data, err := os.ReadFile(resFile)
	if err != nil { return nil, nil }
	return parseSARIF(data, lang)
}

// detectLang returns the primary codeql language for the source tree.
func detectLang(src string) string {
	counts := map[string]int{}
	filepath.WalkDir(src, func(p string, d os.DirEntry, _ error) error {
		if d.IsDir() { return nil }
		switch strings.ToLower(filepath.Ext(p)) {
		case ".py":          counts["python"]++
		case ".go":          counts["go"]++
		case ".js", ".ts":   counts["javascript"]++
		case ".java":        counts["java"]++
		case ".cs":          counts["csharp"]++
		case ".cpp", ".cc":  counts["cpp"]++
		}
		return nil
	})
	best, max := "", 0
	for lang, n := range counts {
		if n > max { best, max = lang, n }
	}
	return best
}

type sarifDoc struct {
	Runs []sarifRun `json:"runs"`
}
type sarifRun struct {
	Results []sarifResult `json:"results"`
}
type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct{ Text string `json:"text"` } `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct{ URI string `json:"uri"` } `json:"artifactLocation"`
			Region struct{ StartLine int `json:"startLine"` } `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

func levelToSev(level string) string {
	switch level {
	case "error":   return "HIGH"
	case "warning": return "MEDIUM"
	default:        return "INFO"
	}
}

func parseSARIF(data []byte, lang string) ([]scanner.Finding, error) {
	var doc sarifDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("codeql: parse SARIF: %w", err)
	}
	var findings []scanner.Finding
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			path, line := "", 0
			if len(r.Locations) > 0 {
				path = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
				line = r.Locations[0].PhysicalLocation.Region.StartLine
			}
			findings = append(findings, scanner.Finding{
				Tool:      "codeql",
				Severity:  scanner.Severity(levelToSev(r.Level)),
				RuleID:    r.RuleID,
				Message:   r.Message.Text,
				Path:      path,
				Line:      line,
				FixSignal: "https://codeql.github.com/codeql-query-help/" + lang + "/" + r.RuleID,
			})
		}
	}
	return findings, nil
}
