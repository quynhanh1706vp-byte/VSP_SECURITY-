package cosign

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs cosign — detects container image signatures (Sigstore).
//
// Zero-config approach: scans opts.Src for Dockerfile / docker-compose.yml,
// extracts image references, and runs `cosign tree <image>` to check if
// signatures/attestations are attached.
//
// Findings:
//   - INFO  — image has N signatures and M attestations (good)
//   - LOW   — image has no signatures (supply-chain risk)
//   - TRACE — image couldn't be reached (network/auth issue; informational)
//
// cosign tree output is human-readable text (no JSON flag), so we parse
// line-based markers.
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "cosign" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("cosign: Src path is required")
	}

	images, err := extractImages(opts.Src)
	if err != nil {
		return nil, fmt.Errorf("cosign: extract images: %w", err)
	}
	if len(images) == 0 {
		// No Dockerfile / docker-compose → nothing to check, not an error
		return nil, nil
	}

	var findings []scanner.Finding
	seen := make(map[string]bool)
	for _, img := range images {
		if seen[img] {
			continue
		}
		seen[img] = true

		f := checkImage(ctx, img)
		findings = append(findings, f)
	}
	return findings, nil
}

// ── Image extraction ──────────────────────────────────────────────────────────

// FROM <image>[:tag][@digest] — handles multi-stage builds (FROM ... AS name)
var fromRegex = regexp.MustCompile(`(?i)^\s*FROM\s+(\S+)`)

// image: <string> in docker-compose.yml
var composeImageRegex = regexp.MustCompile(`(?m)^\s*image:\s*["']?([^\s"'#]+)`)

func extractImages(srcPath string) ([]string, error) {
	var images []string

	err := filepath.Walk(srcPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable files
		}
		if info.IsDir() {
			name := info.Name()
			// Skip heavy / irrelevant dirs
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == ".phase1_backup" || strings.HasPrefix(name, ".phase") {
				return filepath.SkipDir
			}
			return nil
		}
		name := info.Name()
		lower := strings.ToLower(name)
		if lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") ||
			strings.HasSuffix(lower, ".dockerfile") {
			imgs, _ := parseDockerfile(path)
			images = append(images, imgs...)
		}
		if lower == "docker-compose.yml" || lower == "docker-compose.yaml" ||
			lower == "compose.yml" || lower == "compose.yaml" {
			imgs, _ := parseCompose(path)
			images = append(images, imgs...)
		}
		return nil
	})
	return dedupe(images), err
}

func parseDockerfile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var imgs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := fromRegex.FindStringSubmatch(line); m != nil {
			img := m[1]
			// Skip stage aliases ("FROM scratch" or "FROM base AS build")
			if img == "scratch" || strings.Contains(img, "$") {
				continue
			}
			imgs = append(imgs, img)
		}
	}
	return imgs, sc.Err()
}

func parseCompose(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var imgs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := composeImageRegex.FindStringSubmatch(line); m != nil {
			imgs = append(imgs, m[1])
		}
	}
	return imgs, sc.Err()
}

func dedupe(in []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ── Image signature check ─────────────────────────────────────────────────────

func checkImage(ctx context.Context, image string) scanner.Finding {
	// Run: cosign tree <image>
	res, err := scanner.Run(ctx, "cosign", "tree", image)
	if err != nil {
		// Network / auth / image-not-found → informational, not a finding
		return scanner.Finding{
			Tool:     "cosign",
			Severity: scanner.SevTrace,
			RuleID:   "COSIGN-UNREACHABLE",
			Message:  fmt.Sprintf("Cannot check %s: %s", image, truncate(err.Error(), 80)),
			Path:     image,
			Category: scanner.SourceSCA,
			Raw: map[string]any{
				"image": image,
				"error": err.Error(),
			},
		}
	}

	output := string(res.Stdout) + string(res.Stderr)
	sigCount, attCount, sbomCount := countArtifacts(output)

	if sigCount == 0 && attCount == 0 && sbomCount == 0 {
		return scanner.Finding{
			Tool:      "cosign",
			Severity:  scanner.SevLow,
			RuleID:    "COSIGN-UNSIGNED",
			Message:   fmt.Sprintf("Image %s has no signatures or attestations attached", image),
			Path:      image,
			CWE:       "CWE-494", // Download of Code Without Integrity Check
			FixSignal: "Sign image with `cosign sign` or use signed base image",
			Category:  scanner.SourceSCA,
			Raw: map[string]any{
				"image":          image,
				"signatures":     sigCount,
				"attestations":   attCount,
				"sboms":          sbomCount,
			},
		}
	}

	return scanner.Finding{
		Tool:     "cosign",
		Severity: scanner.SevInfo,
		RuleID:   "COSIGN-SIGNED",
		Message: fmt.Sprintf("Image %s: %d signatures, %d attestations, %d SBOMs",
			image, sigCount, attCount, sbomCount),
		Path:     image,
		Category: scanner.SourceSCA,
		Raw: map[string]any{
			"image":        image,
			"signatures":   sigCount,
			"attestations": attCount,
			"sboms":        sbomCount,
		},
	}
}

// countArtifacts parses cosign tree output by tracking sections.
//
// cosign tree output structure:
//
//	📦 Supply Chain Security Related artifacts for an image: <image>
//	└── 🍒 Signatures for an image tag      ← section header
//	   └── 🔐 sha256:abcd...                 ← data line (count as signature)
//	   └── 🔐 sha256:efgh...
//	└── 💾 Attestations for an image tag     ← new section header
//	   └── 🔍 sha256:ijkl...                 ← data line (count as attestation)
//	└── 📦 SBOMs for an image tag            ← new section header
//	   └── 📄 sha256:mnop...                 ← data line (count as sbom)
func countArtifacts(output string) (sig, att, sbom int) {
	section := ""
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		// Detect section headers (contain keyword + "for an image")
		switch {
		case strings.Contains(lower, "signature") && strings.Contains(lower, "for an image"):
			section = "sig"
			continue
		case strings.Contains(lower, "attestation") && strings.Contains(lower, "for an image"):
			section = "att"
			continue
		case strings.Contains(lower, "sbom") && strings.Contains(lower, "for an image"):
			section = "sbom"
			continue
		}
		// Data lines have sha256: hash
		if !strings.Contains(line, "sha256:") {
			continue
		}
		switch section {
		case "sig":
			sig++
		case "att":
			att++
		case "sbom":
			sbom++
		}
	}
	return
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
