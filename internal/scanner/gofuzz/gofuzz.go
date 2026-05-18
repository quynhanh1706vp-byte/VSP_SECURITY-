// Package gofuzz wraps Go built-in fuzzing (Go 1.18+).
// Runs all FuzzXxx functions for a configurable duration.
package gofuzz

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Finding struct {
	Tool     string `json:"tool"`
	Package  string `json:"package"`
	FuzzFunc string `json:"fuzz_func"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Details  string `json:"details"`
	Crash    string `json:"crash,omitempty"`
}

// Discover lists all Fuzz* functions in the project.
func Discover(ctx context.Context, projectDir string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "grep", "-rln", "func Fuzz", "--include=*.go", projectDir)
	out, _ := cmd.Output()
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

// Run executes go test -fuzz for each fuzz target.
// duration per target: 30s default. Set to "30s" / "1m" / "5m".
func Run(ctx context.Context, projectDir string, perTargetDuration string) ([]Finding, error) {
	if perTargetDuration == "" {
		perTargetDuration = "30s"
	}
	var findings []Finding

	// List fuzz targets via go test -list
	cmd := exec.CommandContext(ctx, "go", "test", "-list", "^Fuzz", "./...")
	cmd.Dir = projectDir
	out, _ := cmd.Output()

	pkgs := make(map[string][]string)
	currentPkg := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ok ") || strings.HasPrefix(line, "FAIL ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentPkg = parts[1]
			}
		} else if strings.HasPrefix(line, "Fuzz") {
			pkgs[currentPkg] = append(pkgs[currentPkg], line)
		}
	}

	// Run each fuzz target with timeout
	for pkg, targets := range pkgs {
		for _, fn := range targets {
			tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			runCmd := exec.CommandContext(tctx, "go", "test",
				"-fuzz", "^"+fn+"$",
				"-fuzztime", perTargetDuration,
				"-run", "^$",
				pkg)
			runCmd.Dir = projectDir
			rOut, err := runCmd.CombinedOutput()
			cancel()

			if err != nil && strings.Contains(string(rOut), "failing input") {
				findings = append(findings, Finding{
					Tool:     "gofuzz",
					Package:  pkg,
					FuzzFunc: fn,
					Severity: "high",
					Title:    fmt.Sprintf("Fuzz crash: %s.%s", pkg, fn),
					Details:  string(rOut),
					Crash:    extractCrash(string(rOut)),
				})
			}
		}
	}

	return findings, nil
}

func extractCrash(output string) string {
	idx := strings.Index(output, "failing input written to")
	if idx == -1 {
		return ""
	}
	end := strings.Index(output[idx:], "\n")
	if end == -1 {
		return output[idx:]
	}
	return output[idx : idx+end]
}

// MarshalFindings returns findings as JSON.
func MarshalFindings(findings []Finding) ([]byte, error) {
	return json.MarshalIndent(findings, "", "  ")
}
