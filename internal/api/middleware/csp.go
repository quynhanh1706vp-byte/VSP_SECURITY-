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
		// P4 panel — skip strict CSP, allow inline
		if strings.HasPrefix(r.URL.Path, "/static/panels/") {
			w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; connect-src *;")
			next.ServeHTTP(w, r)
			return
		}
		b := make([]byte, 16)
		rand.Read(b) //nolint:errcheck
		nonce := base64.StdEncoding.EncodeToString(b)
		ctx := context.WithValue(r.Context(), cspKey{}, nonce)
		csp := fmt.Sprintf(
			"default-src 'self'; "+
				"script-src 'self' 'nonce-%s' https://unpkg.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "+
				"style-src 'self' 'nonce-%s' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"img-src 'self' data: blob:; "+
				"connect-src 'self' wss: ws: https://api.anthropic.com https://cdn.jsdelivr.net; "+
				"frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'",
			nonce, nonce,
		)
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetNonce(ctx context.Context) string {
	n, _ := ctx.Value(cspKey{}).(string)
	return n
}

var (
	indexTmplMu   sync.RWMutex
	indexTmpl     *template.Template
	indexTmplPath string
	indexTmplMod  int64
)

type indexData struct{ Nonce string }

// loadIndexTemplate reloads index.html whenever the file changes on disk.
// This allows hot-reload after copying a new static file without restart.
func loadIndexTemplate(staticDir string) (*template.Template, error) {
	path := filepath.Join(staticDir, "index.html")
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("csp: stat index.html: %w", err)
	}
	mtime := info.ModTime().UnixNano()

	indexTmplMu.RLock()
	if indexTmpl != nil && indexTmplPath == path && indexTmplMod == mtime {
		tmpl := indexTmpl
		indexTmplMu.RUnlock()
		return tmpl, nil
	}
	indexTmplMu.RUnlock()

	// Reload
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("csp: read index.html: %w", err)
	}
	tmpl, err := template.New("index").Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("csp: parse index.html: %w", err)
	}
	indexTmplMu.Lock()
	indexTmpl = tmpl
	indexTmplPath = path
	indexTmplMod = mtime
	indexTmplMu.Unlock()
	return tmpl, nil
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
