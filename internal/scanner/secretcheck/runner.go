package secretcheck

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vsp/platform/internal/scanner"
)

type Runner struct{ checker *Checker }

func NewRunner() *Runner       { return &Runner{checker: NewChecker()} }
func (r *Runner) Name() string { return "secretcheck" }

func (r *Runner) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("secretcheck: Src required")
	}
	secrets, err := extractSecrets(opts.Src)
	if err != nil || len(secrets) == 0 {
		return nil, nil
	}
	var findings []scanner.Finding
	for _, raw := range secrets {
		sType := DetectType(raw.value)
		if sType == SecretGeneric {
			continue
		}
		result := r.checker.Check(ctx, sType, raw.value)
		if !result.IsValid {
			continue
		}
		findings = append(findings, scanner.Finding{
			Tool:      "secretcheck",
			Severity:  scanner.SevCritical,
			RuleID:    fmt.Sprintf("live-%s", string(sType)),
			Message:   fmt.Sprintf("LIVE secret confirmed valid: %s at %s:%d", string(sType), raw.file, raw.line),
			Path:      raw.file,
			Line:      raw.line,
			CWE:       "CWE-798",
			FixSignal: fmt.Sprintf("Rotate %s immediately — confirmed active via %s", string(sType), result.Endpoint),
			Raw: map[string]any{
				"secret_type": string(sType),
				"endpoint":    result.Endpoint,
				"status_code": result.StatusCode,
				"checked_at":  result.CheckedAt,
			},
		})
	}
	return findings, nil
}

type rawSecret struct {
	value string
	file  string
	line  int
}

var secretPrefixes = []string{"AKIA", "ASIA", "ghp_", "github_pat_", "sk_live_", "sk_test_", "xoxb-", "xoxp-"}

func extractSecrets(src string) ([]rawSecret, error) {
	var results []rawSecret
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		skip := map[string]bool{".png": true, ".jpg": true, ".gif": true, ".bin": true, ".exe": true, ".zip": true}
		if skip[ext] {
			return nil
		}
		if err := func() error { //nolint:gosec // G122: path from WalkDir, symlinks followed intentionally
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close() // safe: closed per-iteration via closure
			sc := bufio.NewScanner(f)
			lineNum := 0
			for sc.Scan() {
				lineNum++
				line := sc.Text()
				for _, prefix := range secretPrefixes {
					if idx := strings.Index(line, prefix); idx != -1 {
						end := idx + 60
						if end > len(line) {
							end = len(line)
						}
						results = append(results, rawSecret{
							value: strings.Fields(line[idx:end])[0],
							file:  path,
							line:  lineNum,
						})
					}
				}
			}
			return nil
		}(); err != nil {
			return err
		}
		return nil
	})
	return results, err
}
