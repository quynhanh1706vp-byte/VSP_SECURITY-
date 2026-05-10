// Package apisec runs OWASP API Top 10 (2023) checks against API endpoints.
// Combines nuclei templates + custom rule engine.
package apisec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// OWASP API Top 10 (2023) categories
type Category string

const (
	API01 Category = "API1:2023 Broken Object Level Authorization"
	API02 Category = "API2:2023 Broken Authentication"
	API03 Category = "API3:2023 Broken Object Property Level Authorization"
	API04 Category = "API4:2023 Unrestricted Resource Consumption"
	API05 Category = "API5:2023 Broken Function Level Authorization"
	API06 Category = "API6:2023 Unrestricted Access to Sensitive Business Flows"
	API07 Category = "API7:2023 Server Side Request Forgery"
	API08 Category = "API8:2023 Security Misconfiguration"
	API09 Category = "API9:2023 Improper Inventory Management"
	API10 Category = "API10:2023 Unsafe Consumption of APIs"
)

type Finding struct {
	Tool     string   `json:"tool"`
	Category Category `json:"category"`
	URL      string   `json:"url"`
	Method   string   `json:"method"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Details  string   `json:"details"`
	Evidence string   `json:"evidence,omitempty"`
}

type Scanner struct {
	BaseURL    string
	HTTPClient *http.Client
	AuthToken  string
}

func New(baseURL string) *Scanner {
	return &Scanner{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Run executes all API security checks.
func (s *Scanner) Run(ctx context.Context, endpoints []string) ([]Finding, error) {
	var findings []Finding

	for _, ep := range endpoints {
		// API01: Broken Object Level Authorization (BOLA)
		// Try IDs that should be inaccessible (e.g., /users/1 if not authenticated)
		if f := s.checkBOLA(ctx, ep); f != nil {
			findings = append(findings, *f)
		}

		// API02: Authentication checks
		if f := s.checkAuth(ctx, ep); f != nil {
			findings = append(findings, *f)
		}

		// API04: Rate limiting check
		if f := s.checkRateLimit(ctx, ep); f != nil {
			findings = append(findings, *f)
		}

		// API08: Security misconfiguration (headers)
		if f := s.checkSecurityHeaders(ctx, ep); f != nil {
			findings = append(findings, *f)
		}

		// API09: Inventory management (deprecated/test endpoints)
		if f := s.checkInventory(ctx, ep); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// API01: Try unauthenticated access
func (s *Scanner) checkBOLA(ctx context.Context, endpoint string) *Finding {
	url := s.BaseURL + endpoint
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// If unauthenticated request returns 200, it's BOLA risk
	if resp.StatusCode == 200 && (strings.Contains(endpoint, "/users/") || strings.Contains(endpoint, "/orders/")) {
		return &Finding{
			Tool: "apisec", Category: API01, URL: url, Method: "GET",
			Severity: "high",
			Title:    "BOLA: Unauthenticated access to potentially sensitive object",
			Details:  fmt.Sprintf("Endpoint %s returned 200 without auth", endpoint),
		}
	}
	return nil
}

func (s *Scanner) checkAuth(ctx context.Context, endpoint string) *Finding {
	// Check for weak auth indicators
	url := s.BaseURL + endpoint
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "Bearer invalid_token_xyz")
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return &Finding{
			Tool: "apisec", Category: API02, URL: url, Method: "GET",
			Severity: "critical",
			Title:    "Broken Authentication: invalid token accepted",
			Details:  "Endpoint accepted invalid Bearer token",
		}
	}
	return nil
}

// API04: Rate limiting check (send 100 requests, check if any 429)
func (s *Scanner) checkRateLimit(ctx context.Context, endpoint string) *Finding {
	url := s.BaseURL + endpoint
	rateLimited := false
	for i := 0; i < 100; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := s.HTTPClient.Do(req)
		if err != nil {
			break
		}
		if resp.StatusCode == 429 {
			rateLimited = true
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}
	if !rateLimited {
		return &Finding{
			Tool: "apisec", Category: API04, URL: url, Method: "GET",
			Severity: "medium",
			Title:    "No rate limiting detected (100 reqs no 429)",
			Details:  "Endpoint accepts unlimited requests; vulnerable to DoS",
		}
	}
	return nil
}

// API08: Security headers
func (s *Scanner) checkSecurityHeaders(ctx context.Context, endpoint string) *Finding {
	url := s.BaseURL + endpoint
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	missing := []string{}
	required := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "",
		"Content-Security-Policy":   "",
	}
	for h, _ := range required {
		if resp.Header.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		return &Finding{
			Tool: "apisec", Category: API08, URL: url, Method: "GET",
			Severity: "medium",
			Title:    fmt.Sprintf("Missing security headers: %s", strings.Join(missing, ", ")),
			Details:  "Recommended headers per OWASP API Security Top 10",
		}
	}
	return nil
}

// API09: Inventory check (deprecated endpoints)
func (s *Scanner) checkInventory(ctx context.Context, endpoint string) *Finding {
	suspect := []string{"/api/v0/", "/api/old/", "/api/legacy/", "/api/test/", "/api/internal/"}
	for _, prefix := range suspect {
		if strings.HasPrefix(endpoint, prefix) {
			return &Finding{
				Tool: "apisec", Category: API09, URL: s.BaseURL + endpoint, Method: "GET",
				Severity: "low",
				Title:    fmt.Sprintf("Deprecated/test endpoint exposed: %s", prefix),
				Details:  "Should be removed or restricted in production",
			}
		}
	}
	return nil
}

// MarshalFindings returns findings as JSON.
func MarshalFindings(findings []Finding) ([]byte, error) {
	return json.Marshal(findings)
}

// HelperBufferReset is a no-op to use bytes import (apisec_test.go uses).
var _ = bytes.Buffer{}
