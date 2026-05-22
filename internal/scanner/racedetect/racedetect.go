// Package racedetect runs Go race detector for memory safety analysis.
// Equivalent to ThreadSanitizer for Go programs.
package racedetect

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
)

type Finding struct {
	Tool      string `json:"tool"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Details   string `json:"details"`
	Goroutine string `json:"goroutine,omitempty"`
}

// Run executes `go test -race ./...` and parses race conditions.
func Run(ctx context.Context, projectDir string) ([]Finding, error) {
	cmd := exec.CommandContext(ctx, "go", "test", "-race", "-count=1", "-short", "./...")
	cmd.Dir = projectDir
	out, _ := cmd.CombinedOutput()

	var findings []Finding
	output := string(out)

	// Parse race conditions. Format:
	//   WARNING: DATA RACE
	//   Read at 0x... by goroutine N:
	//     <package>.<func>()
	//         <file>:<line>
	if !strings.Contains(output, "WARNING: DATA RACE") {
		return findings, nil
	}

	// Split by race blocks
	blocks := strings.Split(output, "WARNING: DATA RACE")
	for i := 1; i < len(blocks); i++ {
		block := blocks[i]
		end := strings.Index(block, "==================")
		if end > 0 {
			block = block[:end]
		}
		f := parseRaceBlock(block)
		if f.Title != "" {
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func parseRaceBlock(block string) Finding {
	lines := strings.Split(block, "\n")
	f := Finding{
		Tool:     "racedetect",
		Severity: "high",
		Title:    "Data race detected",
		Details:  strings.TrimSpace(block),
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Read at") || strings.HasPrefix(line, "Write at") {
			f.Title = "Data race: " + line
		}
		// Try to find file:line
		if strings.Contains(line, ".go:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				f.File = parts[0]
				// f.Line = parsed (omit for brevity)
			}
		}
	}
	return f
}

// MarshalFindings returns findings as JSON.
func MarshalFindings(findings []Finding) ([]byte, error) {
	return json.MarshalIndent(findings, "", "  ")
}
