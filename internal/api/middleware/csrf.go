package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
)

const csrfHeader = "X-CSRF-Token"
const csrfCookie = "vsp_csrf"

// CSRFProtect validates the double-submit CSRF cookie pattern.
//
// Flow:
//  1. GET /  → server sets vsp_csrf cookie (SameSite=Strict, HttpOnly=false so JS can read)
//  2. POST * → JS reads cookie, sends X-CSRF-Token header
//  3. Middleware compares header == cookie value
//
// Note: this pattern is safe because cross-origin requests cannot read cookies,
// so an attacker cannot set the header to match the cookie value.
func CSRFProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip safe methods and non-API paths
		if r.Method == http.MethodGet ||
			r.Method == http.MethodHead ||
			r.Method == http.MethodOptions {
			// Issue a CSRF token cookie on GET if not present
			if _, err := r.Cookie(csrfCookie); err != nil {
				token := generateCSRFToken()
				// #nosec G124 -- HttpOnly intentionally false: double-submit CSRF requires JS read access.
				// SameSite=Strict + Secure (on HTTPS) provide equivalent protection without breaking the pattern.
				http.SetCookie(w, &http.Cookie{
					Name:     csrfCookie,
					Value:    token,
					Path:     "/",
					SameSite: http.SameSiteStrictMode,
					Secure:   isHTTPS(r),
					HttpOnly: false,
				})
			}
			next.ServeHTTP(w, r)
			return
		}

		// Skip auth endpoints — CSRF not applicable to token-based auth login
		if r.URL.Path == "/api/v1/auth/login" ||
			r.URL.Path == "/api/v1/auth/refresh" ||
			strings.HasPrefix(r.URL.Path, "/api/v1/siem/") {
			next.ServeHTTP(w, r)
			return
		}

		// Skip if using Bearer token auth (API clients, not browser)
		// Browser sessions use cookies; API clients use Authorization header
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			// Bearer token present — CSRF not required (custom header = implicit protection)
			next.ServeHTTP(w, r)
			return
		}

		// Validate double-submit cookie
		cookie, err := r.Cookie(csrfCookie)
		if err != nil || cookie.Value == "" {
			http.Error(w, "CSRF cookie missing", http.StatusForbidden)
			return
		}
		header := r.Header.Get(csrfHeader)
		if header == "" || header != cookie.Value {
			http.Error(w, "CSRF token mismatch", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck
	return base64.URLEncoding.EncodeToString(b)
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}
