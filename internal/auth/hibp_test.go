package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hibpRoundTripper redirects api.pwnedpasswords.com → test server.
type hibpRoundTripper struct{ ts *httptest.Server }

func (rt hibpRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(rt.ts.URL, "http://")
	return http.DefaultTransport.RoundTrip(req)
}

func TestCheckPasswordBreached_Hit(t *testing.T) {
	// SHA-1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	// Prefix=5BAA6, suffix=1E4C9B93F3F0682250B6CF8331B7EE68FD8
	body := `00ABBC91A56124E5BBE0FB000A2D7BD83555:5
1E4C9B93F3F0682250B6CF8331B7EE68FD8:9999999
ZZZZZ:1
`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/range/5BAA6") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()
	hibpClient = &http.Client{Transport: hibpRoundTripper{ts}}

	err := CheckPasswordBreached(context.Background(), "password")
	if err != ErrPasswordBreached {
		t.Fatalf("expected ErrPasswordBreached, got %v", err)
	}
}

func TestCheckPasswordBreached_Miss(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n"))
	}))
	defer ts.Close()
	hibpClient = &http.Client{Transport: hibpRoundTripper{ts}}

	if err := CheckPasswordBreached(context.Background(), "long-and-unique-passphrase-2026"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCheckPasswordBreached_PermissiveOnError(t *testing.T) {
	// Server returns 500 — permissive mode: nil.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()
	hibpClient = &http.Client{Transport: hibpRoundTripper{ts}}
	t.Setenv("VSP_HIBP_REQUIRED", "")

	if err := CheckPasswordBreached(context.Background(), "anything"); err != nil {
		t.Fatalf("permissive mode should return nil, got %v", err)
	}
}

func TestCheckPasswordBreached_StrictOnError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()
	hibpClient = &http.Client{Transport: hibpRoundTripper{ts}}
	t.Setenv("VSP_HIBP_REQUIRED", "1")

	if err := CheckPasswordBreached(context.Background(), "anything"); err != ErrHIBPUnavailable {
		t.Fatalf("strict mode should return ErrHIBPUnavailable, got %v", err)
	}
}
