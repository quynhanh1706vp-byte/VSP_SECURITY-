// internal/api/middleware/csrf_empty_bearer_test.go
// Test cho fix #16: empty Bearer token must not bypass CSRF
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCSRFProtect_EmptyBearerDoesNotBypass: regression test —
// an attacker với "Authorization: Bearer " (empty token) trước đây bypass CSRF.
// Sau patch: phải bị block với 403 vì không có CSRF cookie/header.
func TestCSRFProtect_EmptyBearerDoesNotBypass(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := CSRFProtect(next)

	cases := []string{
		"Bearer ",  // single space
		"Bearer  ", // multiple spaces
		"Bearer\t", // tab
		"Bearer ",  // raw empty
	}
	for _, authValue := range cases {
		called = false
		req := httptest.NewRequest("POST", "/api/v1/users", nil)
		req.Header.Set("Authorization", authValue)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("auth=%q: expected 403, got %d", authValue, w.Code)
		}
		if called {
			t.Errorf("auth=%q: handler should NOT be called", authValue)
		}
	}
}

// TestCSRFProtect_RealBearerBypasses: confirm fix doesn't break
// legitimate Bearer token flow.
func TestCSRFProtect_RealBearerStillBypasses(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := CSRFProtect(next)

	req := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.fake.token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if !called {
		t.Errorf("handler should have been called")
	}
}

// TestCSRFProtect_LogoutWithBearer: end-to-end logout flow.
func TestCSRFProtect_LogoutWithBearer(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := CSRFProtect(next)

	req := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer real-jwt-here")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Errorf("logout handler should be reached when Bearer token present")
	}
}
