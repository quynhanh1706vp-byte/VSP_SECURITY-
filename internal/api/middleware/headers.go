package middleware

import (
	"net/http"
)

// SecurityHeaders adds recommended response headers for CSP, MIME sniffing,
// referrer policy, and clickjacking protection. Intended for dev/proxy use
// to avoid browser blocking of local assets and provide a sane default.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic CSP: allow same-origin scripts/styles and inline styles for
		// the dev stub. Production should generate a stricter CSP.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer-when-downgrade")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		// Let downstream handlers run
		next.ServeHTTP(w, r)
	})
}
