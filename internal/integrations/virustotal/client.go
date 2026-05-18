// Package virustotal provides a client for VirusTotal API v3.
// API docs: https://developers.virustotal.com/reference/files
//
// Free tier limits: 4 req/min, 500/day, 15.5K/month.
// Premium tier: 1000 req/min.
//
// Configuration: set VSP_VT_API_KEY env var. If empty, client returns
// ErrNotConfigured for all calls (graceful degradation).
package virustotal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	apiBase     = "https://www.virustotal.com/api/v3"
	httpTimeout = 15 * time.Second
	cacheTTL    = 24 * time.Hour
)

// ErrNotConfigured indicates VSP_VT_API_KEY is not set.
var ErrNotConfigured = errors.New("virustotal: VSP_VT_API_KEY not set")

// FileReport is the simplified threat assessment for a file hash.
// Only includes fields useful for the SW inventory display.
type FileReport struct {
	SHA256       string    `json:"sha256"`
	Malicious    int       `json:"malicious"`  // # AV engines flagging as malicious
	Suspicious   int       `json:"suspicious"` // # flagging as suspicious
	Undetected   int       `json:"undetected"` // # not detecting threats
	Harmless     int       `json:"harmless"`   // # explicitly clean
	TypeTag      string    `json:"type_tag"`   // e.g. "exe", "elf", "pdf"
	LastAnalysis time.Time `json:"last_analysis"`
	Permalink    string    `json:"permalink"` // https://www.virustotal.com/gui/file/{sha256}
	Verdict      string    `json:"verdict"`   // computed: clean / suspicious / malicious
}

// Client wraps VirusTotal API v3.
type Client struct {
	apiKey     string
	httpClient *http.Client
	cache      map[string]cachedReport
	cacheMu    sync.RWMutex
	// Rate limiter: simple token bucket for free tier (4 req/min)
	rateMu       sync.Mutex
	lastReqTimes []time.Time
}

type cachedReport struct {
	report    *FileReport
	expiresAt time.Time
	err       error // cache negative results too (avoid retry storms)
}

// NewClient creates a VT client. Reads VSP_VT_API_KEY from env.
// If env var is empty, client is non-functional but safe to call.
func NewClient() *Client {
	return &Client{
		apiKey:     os.Getenv("VSP_VT_API_KEY"),
		httpClient: &http.Client{Timeout: httpTimeout},
		cache:      make(map[string]cachedReport),
	}
}

// Configured returns true if API key is set.
func (c *Client) Configured() bool {
	return c.apiKey != ""
}

// GetFileReport fetches threat assessment for a SHA-256 hash.
// Uses cache (24h TTL) and respects free-tier rate limit.
func (c *Client) GetFileReport(ctx context.Context, sha256 string) (*FileReport, error) {
	if !c.Configured() {
		return nil, ErrNotConfigured
	}
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	if len(sha256) != 64 {
		return nil, fmt.Errorf("virustotal: invalid sha256 length=%d", len(sha256))
	}

	// Check cache first
	c.cacheMu.RLock()
	cached, ok := c.cache[sha256]
	c.cacheMu.RUnlock()
	if ok && time.Now().Before(cached.expiresAt) {
		return cached.report, cached.err
	}

	// Rate limit (free tier: 4/min)
	if err := c.waitRateLimit(ctx); err != nil {
		return nil, err
	}

	// Fetch from API
	report, err := c.fetchFromAPI(ctx, sha256)

	// Cache result (positive or negative)
	c.cacheMu.Lock()
	c.cache[sha256] = cachedReport{
		report:    report,
		err:       err,
		expiresAt: time.Now().Add(cacheTTL),
	}
	c.cacheMu.Unlock()

	return report, err
}

func (c *Client) fetchFromAPI(ctx context.Context, sha256 string) (*FileReport, error) {
	url := apiBase + "/files/" + sha256
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// File not in VT database — treat as "no data" not an error
		return &FileReport{
			SHA256:    sha256,
			Verdict:   "unknown",
			Permalink: "https://www.virustotal.com/gui/file/" + sha256,
		}, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("virustotal: invalid API key")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("virustotal: rate limit exceeded")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal: HTTP %d", resp.StatusCode)
	}

	// Parse VT v3 response
	var vt struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Harmless   int `json:"harmless"`
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				LastAnalysisDate int64  `json:"last_analysis_date"`
				TypeTag          string `json:"type_tag"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&vt); decErr != nil {
		return nil, fmt.Errorf("virustotal: parse error: %w", decErr)
	}

	stats := vt.Data.Attributes.LastAnalysisStats
	verdict := computeVerdict(stats.Malicious, stats.Suspicious)

	return &FileReport{
		SHA256:       sha256,
		Malicious:    stats.Malicious,
		Suspicious:   stats.Suspicious,
		Harmless:     stats.Harmless,
		Undetected:   stats.Undetected,
		TypeTag:      vt.Data.Attributes.TypeTag,
		LastAnalysis: time.Unix(vt.Data.Attributes.LastAnalysisDate, 0),
		Permalink:    "https://www.virustotal.com/gui/file/" + sha256,
		Verdict:      verdict,
	}, nil
}

// computeVerdict applies thresholds to malicious/suspicious counts.
func computeVerdict(malicious, suspicious int) string {
	if malicious >= 5 {
		return "malicious"
	}
	if malicious >= 1 || suspicious >= 3 {
		return "suspicious"
	}
	return "clean"
}

// waitRateLimit enforces ≤ 4 requests per 60 seconds (free tier).
func (c *Client) waitRateLimit(ctx context.Context) error {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-60 * time.Second)

	// Drop expired timestamps
	keep := c.lastReqTimes[:0]
	for _, t := range c.lastReqTimes {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	c.lastReqTimes = keep

	// If 4+ recent calls, wait until oldest expires
	if len(c.lastReqTimes) >= 4 {
		waitUntil := c.lastReqTimes[0].Add(60 * time.Second)
		wait := time.Until(waitUntil)
		if wait > 0 {
			c.rateMu.Unlock()
			defer c.rateMu.Lock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
	}
	c.lastReqTimes = append(c.lastReqTimes, time.Now())
	return nil
}

// CacheStats returns cache info for observability.
type CacheStats struct {
	Size       int       `json:"size"`
	Configured bool      `json:"configured"`
	APIKeyLen  int       `json:"api_key_len"`
	StartedAt  time.Time `json:"started_at"`
}

func (c *Client) Stats() CacheStats {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	return CacheStats{
		Size:       len(c.cache),
		Configured: c.Configured(),
		APIKeyLen:  len(c.apiKey),
		StartedAt:  time.Now(),
	}
}
