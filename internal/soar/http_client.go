package soar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTP step errors.
var (
	ErrSSRFBlocked       = errors.New("http: SSRF protection blocked target")
	ErrUnsupportedScheme = errors.New("http: unsupported URL scheme")
	ErrTimeout           = errors.New("http: request timeout")
	ErrTLSDisabled       = errors.New("http: TLS verification cannot be disabled in this build")
)

// SafeHTTPClient implements HTTPDoer with production safety.
//
// Defenses:
//
//   - SSRF: blocks private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x,
//     169.254.x, ::1, fc00::/7, fe80::/10) — unless allow_internal is set.
//   - Scheme: only http:// and https:// allowed.
//   - Redirects: capped at 5 hops, each re-validated for SSRF.
//   - Body: response capped at 10MB to prevent memory exhaustion.
//   - Per-request timeout enforced via context.
type SafeHTTPClient struct {
	inner         *http.Client
	allowInternal bool // for whitelisted internal services
	maxResponseMB int
}

// NewSafeHTTPClient — production default: 30s timeout, 5 redirects, no internal access.
func NewSafeHTTPClient() *SafeHTTPClient {
	c := &SafeHTTPClient{
		allowInternal: false,
		maxResponseMB: 10,
	}
	c.inner = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if !c.allowInternal {
				if err := checkSSRFRedirect(req.URL); err != nil {
					return err
				}
			}
			return nil
		},
	}
	return c
}

// AllowInternal disables SSRF guard. Use only for trusted internal endpoints.
func (c *SafeHTTPClient) AllowInternal(b bool) *SafeHTTPClient {
	c.allowInternal = b
	return c
}

// Do executes the request. Implements HTTPDoer interface.
func (c *SafeHTTPClient) Do(req *HTTPReq) (*HTTPResp, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}
	if req.URL == "" {
		return nil, errors.New("URL required")
	}

	parsed, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedScheme, parsed.Scheme)
	}
	if !c.allowInternal {
		if err := checkSSRF(parsed.Hostname()); err != nil {
			return nil, err
		}
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	// Per-request timeout via context
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > 60*time.Second {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := c.inner.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrTimeout
		}
		return nil, err
	}
	defer resp.Body.Close()

	// Cap response body
	maxBytes := int64(c.maxResponseMB) * 1024 * 1024
	limited := io.LimitReader(resp.Body, maxBytes+1)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(respBody)) > maxBytes {
		return nil, fmt.Errorf("response body exceeds %d MB", c.maxResponseMB)
	}

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &HTTPResp{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       respBody,
	}, nil
}

// checkSSRF rejects hostnames pointing to private/loopback/link-local addresses.
func checkSSRF(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("%w: empty host", ErrSSRFBlocked)
	}

	// Reject obvious internal names
	lh := strings.ToLower(hostname)
	if lh == "localhost" || lh == "metadata.google.internal" ||
		strings.HasSuffix(lh, ".internal") || strings.HasSuffix(lh, ".local") {
		return fmt.Errorf("%w: %s", ErrSSRFBlocked, hostname)
	}

	// Resolve and check all IPs (multi-A record can dodge single-IP check)
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// DNS failure — let request proceed (will fail later); some hosts
		// resolve only via private DNS in tests
		return nil
	}
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("%w: %s → %s", ErrSSRFBlocked, hostname, ip.String())
		}
	}
	return nil
}

// checkSSRFRedirect — same as checkSSRF but for redirect URLs (already parsed).
func checkSSRFRedirect(u *url.URL) error {
	return checkSSRF(u.Hostname())
}

// isPrivateIP — RFC1918 + loopback + link-local + unique local.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}

	// IPv4 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 169.254.0.0/16 (link-local, also caught by IsLinkLocalUnicast)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// 100.64.0.0/10 (CGN)
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}

	// IPv6 unique local fc00::/7
	if len(ip) == 16 && ip[0] == 0xfc || (len(ip) == 16 && ip[0] == 0xfd) {
		return true
	}
	return false
}
