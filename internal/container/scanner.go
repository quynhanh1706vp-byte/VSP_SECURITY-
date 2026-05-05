// Package container provides container image scanning via Trivy CLI.
//
// VSP PRO P0 backend module — for CWPP frontend.
// Wraps `trivy image --format json` and parses results into a typed struct
// suitable for serving via HTTP API to the VSP PRO Container security panel.
package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Severity levels matching Trivy output.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityUnknown  = "UNKNOWN"
)

// Image represents a scanned container image with its summary stats.
type Image struct {
	ID         string    `json:"id"`         // sha256 of image ref
	Ref        string    `json:"ref"`        // e.g. redis:7-alpine
	Digest     string    `json:"digest"`     // sha256 from Trivy
	OS         string    `json:"os"`         // alpine, debian, ubuntu...
	OSVersion  string    `json:"os_version"` // 3.21.7
	SizeMB     int       `json:"size_mb"`
	Layers     int       `json:"layers"`
	Critical   int       `json:"crit"`
	High       int       `json:"high"`
	Medium     int       `json:"med"`
	Low        int       `json:"low"`
	TotalCVE   int       `json:"total_cve"`
	Signed     bool      `json:"signed"`         // cosign signature present
	SBOMAttest bool      `json:"sbom_attested"`  // SBOM attestation present
	ScannedAt  time.Time `json:"scanned_at"`
	Status     string    `json:"status"` // ok | failed | scanning
}

// Vulnerability represents a single CVE found by Trivy.
type Vulnerability struct {
	CVE          string `json:"cve"`
	Severity     string `json:"severity"`
	Library      string `json:"library"`
	Installed    string `json:"installed_version"`
	FixedIn      string `json:"fixed_version,omitempty"`
	Title        string `json:"title"`
	URL          string `json:"url,omitempty"`
	Status       string `json:"status,omitempty"` // fixed | will_not_fix | affected
}

// ScanResult is the full result for one image scan.
type ScanResult struct {
	Image           Image           `json:"image"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	RawJSONSize     int             `json:"raw_json_size"` // bytes — for debugging
	Error           string          `json:"error,omitempty"`
}

// trivyOutput is the partial structure of `trivy image --format json` output
// that we care about. Trivy schema is much richer; we only extract what we need.
type trivyOutput struct {
	Metadata struct {
		OS struct {
			Family  string `json:"Family"`
			Name    string `json:"Name"`
		} `json:"OS"`
		ImageConfig struct {
			Architecture string `json:"architecture"`
			Size         int64  `json:"size"`
			RootFS       struct {
				DiffIDs []string `json:"diff_ids"`
			} `json:"rootfs"`
		} `json:"ImageConfig"`
		RepoDigests []string `json:"RepoDigests"`
	} `json:"Metadata"`
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"VulnerabilityID"`
			PkgName          string   `json:"PkgName"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion,omitempty"`
			Severity         string   `json:"Severity"`
			Title            string   `json:"Title,omitempty"`
			PrimaryURL       string   `json:"PrimaryURL,omitempty"`
			Status           string   `json:"Status,omitempty"`
		} `json:"Vulnerabilities,omitempty"`
	} `json:"Results"`
}

// Scanner manages container image scans with an in-memory cache.
// Scans are async — call Scan(ref) which returns immediately with a job ID,
// then poll GetResult(id) for status.
//
// In production this would use Postgres + Redis; for the P0 module we use
// in-memory storage which is fine for demo + integration testing.
type Scanner struct {
	mu       sync.RWMutex
	results  map[string]*ScanResult // key = image ID
	jobs     map[string]string      // job ID -> image ID (for async tracking)
	trivyBin string
	timeout  time.Duration
}

// NewScanner constructs a scanner. trivyBin defaults to "trivy" (must be in PATH).
func NewScanner() *Scanner {
	return &Scanner{
		results:  make(map[string]*ScanResult),
		jobs:     make(map[string]string),
		trivyBin: "trivy",
		timeout:  5 * time.Minute,
	}
}

// imageID computes a stable ID from image ref.
func imageID(ref string) string {
	h := sha256.Sum256([]byte(ref))
	return "img_" + hex.EncodeToString(h[:8])
}

// ListImages returns all scanned images, sorted by most-recent first.
func (s *Scanner) ListImages() []Image {
	s.mu.RLock()
	defer s.mu.RUnlock()

	imgs := make([]Image, 0, len(s.results))
	for _, r := range s.results {
		imgs = append(imgs, r.Image)
	}
	// Sort by ScannedAt desc — simple insertion sort for small N
	for i := 1; i < len(imgs); i++ {
		for j := i; j > 0 && imgs[j].ScannedAt.After(imgs[j-1].ScannedAt); j-- {
			imgs[j], imgs[j-1] = imgs[j-1], imgs[j]
		}
	}
	return imgs
}

// GetResult returns the full scan result for an image ID, if it exists.
func (s *Scanner) GetResult(imageID string) (*ScanResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.results[imageID]
	return r, ok
}

// Scan runs `trivy image --format json` on the given image ref synchronously
// and stores the result. Returns the image ID for retrieval.
//
// Times out after Scanner.timeout (default 5 min).
func (s *Scanner) Scan(ctx context.Context, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", errors.New("image ref required")
	}

	id := imageID(ref)

	// Mark as scanning
	s.mu.Lock()
	s.results[id] = &ScanResult{
		Image: Image{
			ID:        id,
			Ref:       ref,
			Status:    "scanning",
			ScannedAt: time.Now(),
		},
	}
	s.mu.Unlock()

	// Run trivy with timeout
	scanCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, s.trivyBin,
		"image",
		"--format", "json",
		"--quiet",
		"--scanners", "vuln",
		"--skip-version-check",
		ref,
	)

	out, err := cmd.Output()
	if err != nil {
		s.mu.Lock()
		s.results[id].Image.Status = "failed"
		s.results[id].Error = fmt.Sprintf("trivy exec: %v", err)
		s.mu.Unlock()
		return id, fmt.Errorf("trivy scan failed for %s: %w", ref, err)
	}

	// Parse output
	var raw trivyOutput
	if err := json.Unmarshal(out, &raw); err != nil {
		s.mu.Lock()
		s.results[id].Image.Status = "failed"
		s.results[id].Error = fmt.Sprintf("parse json: %v", err)
		s.mu.Unlock()
		return id, fmt.Errorf("parse trivy output: %w", err)
	}

	// Extract vulnerabilities + count by severity
	result := &ScanResult{
		Image: Image{
			ID:        id,
			Ref:       ref,
			OS:        raw.Metadata.OS.Family,
			OSVersion: raw.Metadata.OS.Name,
			SizeMB:    int(raw.Metadata.ImageConfig.Size / (1024 * 1024)),
			Layers:    len(raw.Metadata.ImageConfig.RootFS.DiffIDs),
			ScannedAt: time.Now(),
			Status:    "ok",
		},
		Vulnerabilities: []Vulnerability{},
		RawJSONSize:     len(out),
	}

	if len(raw.Metadata.RepoDigests) > 0 {
		result.Image.Digest = raw.Metadata.RepoDigests[0]
	}

	for _, target := range raw.Results {
		for _, v := range target.Vulnerabilities {
			vuln := Vulnerability{
				CVE:       v.VulnerabilityID,
				Severity:  v.Severity,
				Library:   v.PkgName,
				Installed: v.InstalledVersion,
				FixedIn:   v.FixedVersion,
				Title:     v.Title,
				URL:       v.PrimaryURL,
				Status:    v.Status,
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)

			switch v.Severity {
			case SeverityCritical:
				result.Image.Critical++
			case SeverityHigh:
				result.Image.High++
			case SeverityMedium:
				result.Image.Medium++
			case SeverityLow:
				result.Image.Low++
			}
		}
	}
	result.Image.TotalCVE = len(result.Vulnerabilities)

	// TODO P1: integrate cosign verify + SBOM attestation lookup here
	// For now leave as false — the module 2 (cosign) will fill these
	result.Image.Signed = false
	result.Image.SBOMAttest = false

	s.mu.Lock()
	s.results[id] = result
	s.mu.Unlock()

	return id, nil
}

// ScanAsync triggers a scan in the background and returns immediately.
// Caller polls GetResult(id) to check status.
func (s *Scanner) ScanAsync(ref string) string {
	id := imageID(ref)
	go func() {
		_, _ = s.Scan(context.Background(), ref)
	}()
	return id
}
