package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
)

type cspKey struct{}

// CSPNonce middleware tạo random nonce mỗi request cho Content-Security-Policy
// Thay thế 'unsafe-inline' bằng nonce-based CSP
func CSPNonce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate 16-byte random nonce
		b := make([]byte, 16)
		rand.Read(b) //nolint:errcheck
		nonce := base64.StdEncoding.EncodeToString(b)

		// Inject nonce vào context để handlers có thể dùng
		ctx := context.WithValue(r.Context(), cspKey{}, nonce)

		// Set CSP header với nonce
		csp := fmt.Sprintf(
			"default-src 'self'; "+
			"script-src 'self' 'nonce-%s' https://unpkg.com https://cdnjs.cloudflare.com; "+
			"style-src 'self' 'nonce-%s' https://unpkg.com; "+
			"img-src 'self' data:; "+
			"connect-src 'self' wss: ws:; "+
			"frame-src 'none'; "+
			"object-src 'none'; "+
			"base-uri 'self'",
			nonce, nonce,
		)
		w.Header().Set("Content-Security-Policy", csp)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetNonce lấy CSP nonce từ context
func GetNonce(ctx context.Context) string {
	n, _ := ctx.Value(cspKey{}).(string)
	return n
}
