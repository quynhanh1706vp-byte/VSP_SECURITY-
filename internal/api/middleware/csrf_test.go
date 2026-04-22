package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCSRFProtect_SoftwareInventoryExempt verifies that the SW Risk agent endpoint
// is exempt from CSRF token verification. This endpoint is called by
// service accounts with Bearer auth + HMAC signature, not browser sessions.
//
// Regression test for BUG-018 (verified fixed 2026-04-22).
func TestCSRFProtect_SoftwareInventoryExempt(t *testing.T) {
	var reachedHandler bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reachedHandler = true
		w.WriteHeader(http.StatusOK)
	})

	handler := CSRFProtect(next)

	// POST without CSRF cookie, without CSRF header, without Bearer token
	req := httptest.NewRequest(http.MethodPost, "/api/v1/software-inventory/report", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reachedHandler {
		t.Fatalf("CSRF middleware rejected software-inventory/report; expected exempt")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 (exempt), got %d", rec.Code)
	}
}

// TestCSRFProtect_UnauthenticatedBrowserPOSTBlocked ensures the exempt list
// doesn't leak — browser-origin POSTs without CSRF token OR Bearer auth must
// still be rejected.
func TestCSRFProtect_UnauthenticatedBrowserPOSTBlocked(t *testing.T) {
	var reachedHandler bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reachedHandler = true
		w.WriteHeader(http.StatusOK)
	})

	handler := CSRFProtect(next)

	// POST to a non-exempt path, no Bearer, no CSRF token
	req := httptest.NewRequest(http.MethodPost, "/api/v1/poam/sync", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reachedHandler {
		t.Fatalf("CSRF middleware allowed POST without token; expected rejected")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403 Forbidden, got %d", rec.Code)
	}
}

// TestCSRFProtect_BearerTokenBypassesCSRF confirms the documented behavior
// that Bearer-authenticated API clients skip CSRF (custom header =
// implicit origin protection).
func TestCSRFProtect_BearerTokenBypassesCSRF(t *testing.T) {
	var reachedHandler bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reachedHandler = true
		w.WriteHeader(http.StatusOK)
	})

	handler := CSRFProtect(next)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/poam/sync", nil)
	req.Header.Set("Authorization", "Bearer fake.jwt.token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reachedHandler {
		t.Fatalf("CSRF middleware rejected Bearer-authenticated request; expected allowed")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with Bearer auth, got %d", rec.Code)
	}
}
