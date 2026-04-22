package trufflehog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs trufflehog — secret scanner with credential verification.
// Unlike gitleaks (regex-only), trufflehog actively verifies credentials
// against live APIs. Verified findings are treated as CRITICAL.
//
// Output format: JSONL — one JSON object per line on stdout.
// Progress/error messages go to stderr (via --json they're level:info logs,
// but trufflehog ALSO emits them to stdout as JSON with "level" field).
// The parser filters to only lines containing "SourceMetadata".
//
// Finding shape (filesystem source):
//
//	{ "SourceMetadata": {"Data": {"Filesystem": {"file": "...", "line": N}}},
//	  "DetectorName": "AWS", "DetectorDescription": "...",
//	  "Verified": true, "Redacted": "AKIA...", "Raw": "AKIA...SECRETPART",
//	  "ExtraData": {"account": "...", "is_canary": "true"} }
//
// Security note: Raw contains the full secret. We only persist Redacted
// and a truncated Raw prefix for debugging. Full Raw is never logged.
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "trufflehog" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("trufflehog: Src path is required")
	}

	args := []string{
		"filesystem",
		"--json",
		"--no-verification", // disabled by default — avoid external API calls during CI
		"--no-update",       // disable update check network call
		opts.Src,
	}
	if extra, ok := opts.ExtraArgs["trufflehog"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "trufflehog", args...)
	if err != nil {
		return nil, err
	}

	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type trufflehogFinding struct {
	SourceMetadata        sourceMetadata `json:"SourceMetadata"`
	SourceName            string         `json:"SourceName"`
	DetectorName          string         `json:"DetectorName"`
	DetectorDescription   string         `json:"DetectorDescription"`
	DecoderName           string         `json:"DecoderName"`
	Verified              bool           `json:"Verified"`
	VerificationFromCache bool           `json:"VerificationFromCache"`
	VerificationError     string         `json:"VerificationError"`
	Raw                   string         `json:"Raw"`
	RawV2                 string         `json:"RawV2"`
	Redacted              string         `json:"Redacted"`
	ExtraData             map[string]any `json:"ExtraData"`
}

type sourceMetadata struct {
	Data struct {
		Filesystem *fsSource     `json:"Filesystem,omitempty"`
		Github     *githubSource `json:"Github,omitempty"`
		Git        *gitSource    `json:"Git,omitempty"`
	} `json:"Data"`
}

type fsSource struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

type githubSource struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Link       string `json:"link"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
}

type gitSource struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
}

// parse handles JSONL output. Each line is either:
//   - A log entry with "level" field (ignore)
//   - A finding with "SourceMetadata" field (convert)
//
// Malformed lines are skipped silently (trufflehog sometimes emits partial
// output under cancellation).
func parse(data []byte) ([]scanner.Finding, error) {
	var findings []scanner.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	// Some secrets (e.g. private keys) are multi-line within the JSON — bufio
	// default buffer (64KB) is usually enough; bump to 1MB for safety.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	for sc.Scan() {
		lineBytes := sc.Bytes()
		// Fast filter: skip log lines
		if !bytes.Contains(lineBytes, []byte(`"SourceMetadata"`)) {
			continue
		}

		var f trufflehogFinding
		if err := json.Unmarshal(lineBytes, &f); err != nil {
			// Skip malformed; don't fail the whole scan
			continue
		}

		// Skip entries without any redacted form (false positives from
		// unparseable detectors).
		if f.Redacted == "" {
			continue
		}

		path, line := extractLocation(f.SourceMetadata)

		severity := scanner.Severity("HIGH")
		if f.Verified {
			severity = scanner.Severity("CRITICAL")
		}

		// Truncate Raw for storage — never persist full secret
		rawPreview := f.Raw
		if len(rawPreview) > 24 {
			rawPreview = rawPreview[:24] + "..."
		}

		findings = append(findings, scanner.Finding{
			Tool:     "trufflehog",
			Severity: severity,
			RuleID:   f.DetectorName,
			Message: fmt.Sprintf("%s credential detected (verified=%t): %s",
				f.DetectorName, f.Verified, f.Redacted),
			Path: path,
			Line: line,
			CWE:  "CWE-798", // Use of Hard-coded Credentials
			FixSignal: fmt.Sprintf(
				"Rotate the %s credential immediately. Remove from VCS history (git filter-branch or BFG). Use a secrets manager.",
				f.DetectorName),
			Raw: map[string]any{
				"detector_description": f.DetectorDescription,
				"verified":             f.Verified,
				"decoder":              f.DecoderName,
				"redacted":             f.Redacted,
				"raw_preview":          rawPreview,
				"extra":                f.ExtraData,
			},
		})
	}

	if err := sc.Err(); err != nil {
		return findings, fmt.Errorf("trufflehog: scan output: %w", err)
	}

	return findings, nil
}

func extractLocation(meta sourceMetadata) (string, int) {
	switch {
	case meta.Data.Filesystem != nil:
		return meta.Data.Filesystem.File, meta.Data.Filesystem.Line
	case meta.Data.Github != nil:
		return meta.Data.Github.File, meta.Data.Github.Line
	case meta.Data.Git != nil:
		return meta.Data.Git.File, meta.Data.Git.Line
	}
	return "", 0
}
