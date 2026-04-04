package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type cspKey struct{}

func CSPNonce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 16)
		rand.Read(b) //nolint:errcheck
		nonce := base64.StdEncoding.EncodeToString(b)
		ctx := context.WithValue(r.Context(), cspKey{}, nonce)
		csp := fmt.Sprintf(
			"default-src 'self'; "+
				"script-src 'self' 'nonce-%s' https://unpkg.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "+
				"style-src 'self' 'nonce-%s' https://unpkg.com https://fonts.googleapis.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"img-src 'self' data: blob:; "+
				"connect-src 'self' wss: ws: https://api.anthropic.com; "+
				"frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'",
			nonce, nonce,
		)
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetNonce(ctx context.Context) string {
	n, _ := ctx.Value(cspKey{}).(string)
	return n
}

var (
	indexTmplOnce sync.Once
	indexTmpl     *template.Template
	indexTmplErr  error
)

type indexData struct{ Nonce string }

func loadIndexTemplate(staticDir string) (*template.Template, error) {
	indexTmplOnce.Do(func() {
		path := filepath.Join(staticDir, "index.html")
		raw, err := os.ReadFile(path)
		if err != nil {
			indexTmplErr = fmt.Errorf("csp: read index.html: %w", err)
			return
		}
		indexTmpl, indexTmplErr = template.New("index").Parse(string(raw))
	})
	return indexTmpl, indexTmplErr
}

func ServeIndexWithNonce(staticDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := loadIndexTemplate(staticDir)
		if err != nil {
			http.Error(w, "index not found", http.StatusNotFound)
			return
		}
		nonce := GetNonce(r.Context())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := tmpl.Execute(w, indexData{Nonce: nonce}); err != nil {
			http.Error(w, "render error", http.StatusInternalServerError)
		}
	}
}

func InjectNonceIntoHTML(html, nonce string) string {
	html = strings.ReplaceAll(html, "<script>", fmt.Sprintf(`<script nonce="%s">`, nonce))
	html = strings.ReplaceAll(html, "<style>", fmt.Sprintf(`<style nonce="%s">`, nonce))
	return html
}
