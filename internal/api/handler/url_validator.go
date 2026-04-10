package handler

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// validateScanURL validates a user-supplied scan target URL.
// Blocks SSRF by rejecting private/internal hosts and non-http(s) schemes.
// Allows both http and https (unlike webhook which requires https only)
// because DAST scans may target internal staging over http.
// In production, consider restricting to https-only.
func validateScanURL(rawURL string) error {
	if rawURL == "" {
		return nil
	}
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}

	// Block private/internal ranges — SSRF protection
	blocked := []string{
		"localhost", "127.", "0.0.0.0", "::1",
		"169.254.",                                 // link-local
		"10.",                                      // RFC1918
		"192.168.",                                 // RFC1918
		"172.16.", "172.17.", "172.18.", "172.19.", // RFC1918
		"172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.",
		"172.28.", "172.29.", "172.30.", "172.31.",
		"metadata.google", "metadata.aws", // cloud metadata
		"100.64.", "100.65.", "100.66.", "100.67.", // CGNAT
	}
	for _, b := range blocked {
		if strings.HasPrefix(host, b) || host == strings.TrimSuffix(b, ".") {
			return fmt.Errorf("host %q is not allowed (private/internal)", host)
		}
	}

	// DNS resolution check — prevent DNS rebinding attacks
	ips, err := net.LookupHost(host)
	if err != nil {
		// Unknown host — allow (scanner will handle connection error)
		return nil
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() ||
			parsed.IsLinkLocalMulticast() || parsed.IsUnspecified() {
			return fmt.Errorf("URL resolves to private IP %s — blocked (SSRF protection)", ip)
		}
	}
	return nil
}
