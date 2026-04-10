package middleware

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
)

const (
	SessionCookieName = "vsp_session"
	SessionCookiePath = "/"
)

// SetSessionCookie — gọi sau login thành công thay vì trả token trong JSON body
func SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     SessionCookiePath,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie — gọi khi logout
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     SessionCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// CookieAuthMiddleware — đọc JWT từ cookie, fallback Bearer header
// Dùng auth.Middleware() của VSP để parse/validate JWT
func CookieSessionMiddleware(jwtSecret string, keyStore auth.APIKeyStore) func(http.Handler) http.Handler {
	// Reuse existing auth.Middleware (handles Bearer + API key)
	bearerMW := auth.Middleware(jwtSecret, keyStore)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Block token in URL query param (SSE legacy — security fix)
			if r.URL.Query().Get("token") != "" {
				http.Error(w, `{"error":"token in URL not permitted — use cookie or Authorization header"}`,
					http.StatusBadRequest)
				return
			}

			// Inject cookie token into Authorization header
			// nếu chưa có Bearer header (browser request)
			if r.Header.Get("Authorization") == "" {
				if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
					// Clone request để không mutate original
					r2 := r.Clone(r.Context())
					r2.Header.Set("Authorization", "Bearer "+c.Value)
					// Delegate vào existing middleware
					bearerMW(next).ServeHTTP(w, r2)
					return
				}
			}

			// Fallback: Bearer header hoặc API key (existing flow)
			bearerMW(next).ServeHTTP(w, r)
		})
	}
}

// AuthCheckHandler — GET /api/v1/auth/check
// FE dùng để kiểm tra session còn valid không (thay thế localStorage decode)
func AuthCheckHandler(jwtSecret string, keyStore auth.APIKeyStore) http.HandlerFunc {
	mw := auth.Middleware(jwtSecret, keyStore)

	return func(w http.ResponseWriter, r *http.Request) {
		// Inject cookie → header nếu cần
		if r.Header.Get("Authorization") == "" {
			if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
				r2 := r.Clone(r.Context())
				r2.Header.Set("Authorization", "Bearer "+c.Value)
				r = r2
			}
		}

		called := false
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			claims, _ := auth.FromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"authenticated":true,"role":"` + claims.Role + `","tenant_id":"` + claims.TenantID + `"}`))
		})).ServeHTTP(w, r)

		if !called {
			// middleware đã trả 401 — clear cookie
			ClearSessionCookie(w)
		}
	}
}
