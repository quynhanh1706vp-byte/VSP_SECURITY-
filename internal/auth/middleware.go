package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

// ── Context keys ──────────────────────────────────────────────────────────────

type contextKey string

const (
	CtxUserID   contextKey = "user_id"
	CtxTenantID contextKey = "tenant_id"
	CtxRole     contextKey = "role"
	CtxEmail    contextKey = "email"
)

// ── Claims ────────────────────────────────────────────────────────────────────

// Claims holds the parsed identity from JWT or API key.
type Claims struct {
	UserID   string
	TenantID string
	Role     string
	Email    string
}

func FromContext(ctx context.Context) (Claims, bool) {
	uid, ok1 := ctx.Value(CtxUserID).(string)
	tid, ok2 := ctx.Value(CtxTenantID).(string)
	role, _ := ctx.Value(CtxRole).(string)
	email, _ := ctx.Value(CtxEmail).(string)
	if !ok1 || !ok2 || uid == "" || tid == "" {
		return Claims{}, false
	}
	return Claims{UserID: uid, TenantID: tid, Role: role, Email: email}, true
}

// ── APIKeyStore interface ─────────────────────────────────────────────────────

// APIKeyStore is implemented by the store layer.
type APIKeyStore interface {
	// ValidateAPIKey checks the key, updates last_used, and returns the owner's claims.
	ValidateAPIKey(ctx context.Context, rawKey string) (Claims, error)
}

// ── Middleware ────────────────────────────────────────────────────────────────

// Middleware returns a chi-compatible auth middleware.
// It tries X-API-Key first, then Authorization: Bearer JWT.
// On success it injects Claims into the request context.
func Middleware(jwtSecret string, keyStore APIKeyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var claims Claims
			var ok bool

			// 1. Try API Key (CI/CD integration path)
			if k := r.Header.Get("X-API-Key"); k != "" {
				c, err := keyStore.ValidateAPIKey(r.Context(), k)
				if err != nil {
					log.Warn().Str("ip", r.RemoteAddr).Err(err).Msg("invalid api key")
					http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
					return
				}
				claims, ok = c, true
			}

			// 2. Try Bearer JWT (browser/UI path)
			if !ok {
				bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				if bearer != "" {
					c, err := parseJWT(bearer, jwtSecret)
					if err != nil {
						log.Warn().Str("ip", r.RemoteAddr).Err(err).Msg("invalid jwt")
						http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
						return
					}
					claims, ok = c, true
				}
			}

			if !ok {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}

			ctx := injectClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns middleware that enforces a minimum role level.
// Role hierarchy: admin > analyst > dev > auditor
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := FromContext(r.Context())
			if !ok || !allowed[c.Role] {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ── JWT helpers ───────────────────────────────────────────────────────────────

type jwtClaims struct {
	UserID   string `json:"uid"`
	TenantID string `json:"tid"`
	Role     string `json:"role"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}

// IssueJWT creates a signed JWT for the given user.
func IssueJWT(secret string, c Claims, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwtClaims{
		UserID:   c.UserID,
		TenantID: c.TenantID,
		Role:     c.Role,
		Email:    c.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func parseJWT(tokenStr, secret string) (Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwtClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return Claims{}, err
	}
	c, ok := token.Claims.(*jwtClaims)
	if !ok {
		return Claims{}, jwt.ErrTokenInvalidClaims
	}
	return Claims{
		UserID:   c.UserID,
		TenantID: c.TenantID,
		Role:     c.Role,
		Email:    c.Email,
	}, nil
}

func injectClaims(ctx context.Context, c Claims) context.Context {
	ctx = context.WithValue(ctx, CtxUserID, c.UserID)
	ctx = context.WithValue(ctx, CtxTenantID, c.TenantID)
	ctx = context.WithValue(ctx, CtxRole, c.Role)
	ctx = context.WithValue(ctx, CtxEmail, c.Email)
	return ctx
}
