package auth

import (
	"context"
	"crypto/rand"
	"fmt"
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

// Blacklist interface — implemented by auth.TokenBlacklist
type BlacklistChecker interface {
	IsRevoked(ctx context.Context, tokenID string) bool
	IsUserRevoked(ctx context.Context, userID string, issuedAt time.Time) bool
}

// SetBlacklist wires a blacklist checker into JWT validation
var globalBlacklist BlacklistChecker

func SetBlacklist(b BlacklistChecker) { globalBlacklist = b }

// IssueJWT creates a signed JWT for the given user.
func IssueJWT(secret string, c Claims, ttl time.Duration) (string, error) {
	now := time.Now()
	// Generate unique JWT ID for revocation support
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("jti generate: %w", err)
	}
	jti := fmt.Sprintf("%x", jtiBytes)

	claims := jwtClaims{
		UserID:   c.UserID,
		TenantID: c.TenantID,
		Role:     c.Role,
		Email:    c.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
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
	// Check blacklist if configured
	if globalBlacklist != nil {
		jti := c.ID // JWT ID
		if jti != "" && globalBlacklist.IsRevoked(context.Background(), jti) {
			return Claims{}, fmt.Errorf("token revoked")
		}
		if globalBlacklist.IsUserRevoked(context.Background(), c.UserID, c.IssuedAt.Time) {
			return Claims{}, fmt.Errorf("user tokens revoked")
		}
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

// TokenFromQuery returns middleware cho SSE/WS — đọc JWT từ ?token= query param.
// SSE không thể set Authorization header nên dùng query param thay thế.
func TokenFromQuery(jwtSecret string, keyStore APIKeyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var claims Claims
			var ok bool

			// 1. Thử query param ?token=
			if token := r.URL.Query().Get("token"); token != "" {
				c, err := parseJWT(token, jwtSecret)
				if err == nil {
					claims, ok = c, true
				}
			}

			// 2. Fallback: Authorization header (WS có thể set header)
			if !ok {
				if bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); bearer != "" {
					c, err := parseJWT(bearer, jwtSecret)
					if err == nil {
						claims, ok = c, true
					}
				}
			}

			// 3. Fallback: X-API-Key
			if !ok {
				if k := r.Header.Get("X-API-Key"); k != "" {
					c, err := keyStore.ValidateAPIKey(r.Context(), k)
					if err == nil {
						claims, ok = c, true
					}
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

// InjectForTest injects Claims into context for use in unit tests.
// Do NOT use in production code.
func InjectForTest(ctx context.Context, c Claims) context.Context {
	return injectClaims(ctx, c)
}
