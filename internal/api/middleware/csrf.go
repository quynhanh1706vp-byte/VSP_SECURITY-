package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
)

const csrfHeader = "X-CSRF-Token"
const csrfCookie = "vsp_csrf"

// csrfExemptPaths lists endpoints that bypass CSRF entirely.
// Reason for each:
//
//	/auth/login              — no auth context yet, sets the cookie
//	/auth/refresh            — refresh tokens are origin-bound by SameSite
//	/software-inventory/report — agent endpoint (Bearer + HMAC, no browser)
//	/siem/                   — SIEM ingestion (Bearer + IP allowlist)
var csrfExemptPaths = []string{
	"/api/v1/auth/login",
	"/api/v1/auth/refresh",
	"/api/v1/software-inventory/report",
}
var csrfExemptPrefixes = []string{"/api/v1/siem/"}

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

		// Exact-match exempt paths
		for _, p := range csrfExemptPaths {
			if r.URL.Path == p {
				next.ServeHTTP(w, r)
				return
			}
		}
		// Prefix exempts
		for _, p := range csrfExemptPrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// X-Agent-Key bypass — endpoint agents authenticate via this header
		// per request and never carry browser cookies, so double-submit CSRF
		// doesn't apply. Handler verifies the key against agents.api_key_hash
		// before doing anything stateful (store.GetAgentByAPIKeyHash).
		if k := r.Header.Get("X-Agent-Key"); k != "" && len(k) >= 16 {
			next.ServeHTTP(w, r)
			return
		}

		// Bearer token bypass — but only for non-empty tokens.
		// FIX 2026-04-29: "Bearer " (with empty/whitespace token) previously
		// bypassed CSRF, allowing attacker to inject empty Authorization header
		// and skip CSRF validation. Now require non-empty token after the prefix.
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
			if token != "" {
				// Real Bearer token present — CSRF not required
				// (custom Authorization header = implicit cross-origin protection)
				next.ServeHTTP(w, r)
				return
			}
			// "Bearer " with empty token falls through to CSRF check below
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
