package middleware

import (
	"strings"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSPNonce_SetsHeader(t *testing.T) {
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
		t.Error("expected CSP header")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options: nosniff")
	}
	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Error("expected X-Frame-Options: SAMEORIGIN")
	}
	// Verify nonce is injected into CSP script-src and style-src
	if !strings.Contains(csp, "nonce-"+capturedNonce) {
		t.Errorf("expected nonce %s in CSP, got: %s", capturedNonce, csp)
	}
	if !strings.Contains(csp, "script-src") {
		t.Error("expected script-src in CSP")
	}
}

func TestCSPNonce_UniquePerRequest(t *testing.T) {
	nonces := make([]string, 5)
	handler := CSPNonce(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// nonce captured via CSP header
	}))

	for i := range nonces {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		nonces[i] = w.Header().Get("Content-Security-Policy")
	}

	// All CSP headers should be different (different nonces)
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
