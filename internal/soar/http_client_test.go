package soar

import (
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false}, // outside private range
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"100.64.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"fe80::1", true},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Errorf("invalid IP: %s", tt.ip)
			continue
		}
		got := isPrivateIP(ip)
		if got != tt.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestCheckSSRF_LocalhostBlocked(t *testing.T) {
	if err := checkSSRF("localhost"); err == nil {
		t.Error("expected localhost blocked")
	}
}

func TestCheckSSRF_MetadataServiceBlocked(t *testing.T) {
	if err := checkSSRF("metadata.google.internal"); err == nil {
		t.Error("expected metadata service blocked")
	}
}

func TestCheckSSRF_PublicAllowed(t *testing.T) {
	// google.com should resolve to public IP
	err := checkSSRF("google.com")
	// Could fail due to DNS in test env — just check it's not SSRF blocked
	if err != nil && err == ErrSSRFBlocked {
		t.Errorf("public domain blocked as SSRF: %v", err)
	}
}

func TestSafeHTTPClient_NoURL(t *testing.T) {
	c := NewSafeHTTPClient()
	_, err := c.Do(&HTTPReq{})
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestSafeHTTPClient_BadScheme(t *testing.T) {
	c := NewSafeHTTPClient()
	_, err := c.Do(&HTTPReq{URL: "ftp://example.com"})
	if err == nil {
		t.Error("expected scheme error")
	}
}
