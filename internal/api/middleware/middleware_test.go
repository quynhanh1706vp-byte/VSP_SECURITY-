package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSPNonce_SetsHeader(t *testing.T) {
	// Phase 1 of VSP-CSP-001 (commit 7228c6f) applies PanelCSP to both
	// panel and non-panel routes while inline handlers in index.html are
	// refactored. The nonce is still generated and placed in the request
	// context (used by InjectNonceIntoHTML) but is NOT embedded in the
	// CSP header itself until Phase 2. See docs/CSP_HARDENING_ROADMAP.md.
	var capturedNonce string
	handler := CSPNonce(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedNonce = GetNonce(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if capturedNonce == "" {
		t.Error("expected non-empty nonce in context")
	}

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("expected CSP header")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options: nosniff")
	}
	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Error("expected X-Frame-Options: SAMEORIGIN")
	}

	// Phase 1 invariants — these must NEVER appear in any response.
	for _, banned := range []string{
		"default-src *",
		"connect-src *",
		"script-src *",
		"style-src *",
		"'unsafe-eval'",
		"frame-ancestors *",
	} {
		if strings.Contains(csp, banned) {
			t.Errorf("CSP contains banned pattern %q: %s", banned, csp)
		}
	}

	// Phase 1 positive invariants.
	for _, required := range []string{
		"script-src",
		"frame-ancestors 'self'",
		"object-src 'none'",
	} {
		if !strings.Contains(csp, required) {
			t.Errorf("CSP missing required directive %q: %s", required, csp)
		}
	}
}

func TestCSPNonce_UniquePerRequest(t *testing.T) {
	// The CSP header itself is currently static (Phase 1), so uniqueness
	// is verified via the request context where InjectNonceIntoHTML reads
	// the per-request nonce.
	nonces := make([]string, 5)

	for i := range nonces {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		// Capture via a second wrapper that reads the nonce before the
		// inner handler sees the request.
		var got string
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = GetNonce(r.Context())
		})
		CSPNonce(inner).ServeHTTP(w, req)
		nonces[i] = got
	}

	for i := range nonces {
		if nonces[i] == "" {
			t.Errorf("nonce[%d] is empty", i)
		}
	}
	for i := 1; i < len(nonces); i++ {
		if nonces[i] == nonces[0] {
			t.Errorf("nonce[%d] == nonce[0] — nonces should be unique per request", i)
		}
	}
}

func TestGetNonce_EmptyContext(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	nonce := GetNonce(req.Context())
	if nonce != "" {
		t.Errorf("expected empty nonce for context without CSP, got %q", nonce)
	}
}

func TestRequestLogger_SetsReqID(t *testing.T) {
	handler := RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(3, 60*1000000000) // 3 req/minute

	// First 3 should pass
	for i := 0; i < 3; i++ {
		if !rl.Allow("test-key") {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 4th should be blocked
	if rl.Allow("test-key") {
		t.Error("4th request should be blocked")
	}
}

func TestRateLimiter_DifferentKeys(t *testing.T) {
	rl := NewRateLimiter(2, 60*1000000000)

	rl.Allow("key-a")
	rl.Allow("key-a")
	// key-a is now at limit

	// key-b should still be allowed
	if !rl.Allow("key-b") {
		t.Error("key-b should be allowed (different key)")
	}
}

func TestRateLimiterMiddleware_429(t *testing.T) {
	rl := NewRateLimiter(1, 60*1000000000)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request passes
	req1 := httptest.NewRequest("GET", "/", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", w1.Code)
	}

	// Second request blocked
	req2 := httptest.NewRequest("GET", "/", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", w2.Code)
	}
}

func TestInjectNonceIntoHTML(t *testing.T) {
	html := "<script>alert(1)</script><style>body{}</style>"
	result := InjectNonceIntoHTML(html, "test-nonce-123")

	expected := `<script nonce="test-nonce-123">alert(1)</script><style nonce="test-nonce-123">body{}</style>`
	if result != expected {
		t.Errorf("got %q want %q", result, expected)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Phase 1 VSP-CSP-001 invariants — added in commit fix/ci-pre-existing-failures.
// See docs/CSP_HARDENING_ROADMAP.md.
// ═══════════════════════════════════════════════════════════════════════

func TestPanelCSP_NoWildcards(t *testing.T) {
	csp := PanelCSP()
	for _, banned := range []string{
		"default-src *",
		"connect-src *",
		"script-src *",
		"style-src *",
		"'unsafe-eval'",
		"frame-ancestors *",
	} {
		if strings.Contains(csp, banned) {
			t.Errorf("PanelCSP contains banned %q: %s", banned, csp)
		}
	}
	// Required directives.
	for _, required := range []string{
		"default-src 'self'",
		"frame-ancestors 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
	} {
		if !strings.Contains(csp, required) {
			t.Errorf("PanelCSP missing %q: %s", required, csp)
		}
	}
}

func TestIsPanelPath(t *testing.T) {
	tests := map[string]bool{
		"/panels/users.html":                true,
		"/panels/":                          true,
		"/static/panels/p4_compliance.html": true,
		"/static/panels/":                   true,
		"/p4":                               true,
		"/":                                 false,
		"/api/v1/findings":                  false,
		"/static/js/app.js":                 false,
		"/p4/extra":                         false, // only exact /p4 matches
		"/panelsx/users.html":               false, // boundary: not /panels/
	}
	for path, want := range tests {
		if got := IsPanelPath(path); got != want {
			t.Errorf("IsPanelPath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestCSPNonce_PanelPathUsesPanelCSP(t *testing.T) {
	handler := CSPNonce(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/panels/users.html", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if csp != PanelCSP() {
		t.Errorf("panel path should use PanelCSP()\ngot:  %s\nwant: %s", csp, PanelCSP())
	}
}
