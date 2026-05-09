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
	CtxUserID    contextKey = "user_id"
	CtxTenantID  contextKey = "tenant_id"
	CtxRole      contextKey = "role"
	CtxEmail     contextKey = "email"
	CtxJTI       contextKey = "jti"
	CtxExpiresAt contextKey = "exp"
)

// ── Claims ────────────────────────────────────────────────────────────────────

// Claims holds the parsed identity from JWT or API key.
type Claims struct {
	UserID    string
	TenantID  string
	Role      string
	Email     string
	JTI       string    // JWT ID — for token revocation
	ExpiresAt time.Time // for blacklist TTL calculation
}

func FromContext(ctx context.Context) (Claims, bool) {
	uid, ok1 := ctx.Value(CtxUserID).(string)
	tid, ok2 := ctx.Value(CtxTenantID).(string)
	role, _ := ctx.Value(CtxRole).(string)
	email, _ := ctx.Value(CtxEmail).(string)
	jti, _ := ctx.Value(CtxJTI).(string)
	exp, _ := ctx.Value(CtxExpiresAt).(time.Time)
	if !ok1 || !ok2 || uid == "" || tid == "" {
		return Claims{}, false
	}
	return Claims{
		UserID:    uid,
		TenantID:  tid,
		Role:      role,
		Email:     email,
		JTI:       jti,
		ExpiresAt: exp,
	}, true
}

// ── APIKeyStore interface ─────────────────────────────────────────────────────

// APIKeyStore is implemented by the store layer.
type APIKeyStore interface {
	// ValidateAPIKey checks the key, updates last_used, and returns the owner's claims.
	ValidateAPIKey(ctx context.Context, rawKey string) (Claims, error)
}

// L9 2026-05-09: tenant slug→UUID resolver.
//
// Background: dev-mint JWTs and some legacy tokens carry the tenant
// slug ("default") in the tenant_id claim, while every DB column is
// uuid. By the time claims reach a handler we want them to ALWAYS
// hold the UUID, otherwise every handler has to remember to call
// resolveTenantUUID — which historically nine handlers forgot,
// surfacing as 500s, silent zero-row reads, and missed audit emits.
//
// The gateway wires SetClaimsTenantResolver once at startup with a
// DB-backed lookup; tests/non-DB contexts get the identity default.
var claimsTenantResolver = func(ctx context.Context, raw string) string { return raw }

// SetClaimsTenantResolver wires a slug→UUID lookup that the auth
// middleware uses to canonicalise Claims.TenantID before injecting
// into the request context. Idempotent; safe to call once at startup.
func SetClaimsTenantResolver(fn func(ctx context.Context, raw string) string) {
	if fn != nil {
		claimsTenantResolver = fn
	}
}

// canonicalizeTenant rewrites a slug-bearing TenantID to its UUID via
// the registered resolver. Empty / already-UUID values pass through.
func canonicalizeTenant(ctx context.Context, c Claims) Claims {
	if c.TenantID == "" {
		return c
	}
	// Cheap UUID format check — same as handler/audit_helper.go's
	// looksLikeUUID, replicated here to avoid an import cycle.
	if len(c.TenantID) == 36 &&
		c.TenantID[8] == '-' && c.TenantID[13] == '-' &&
		c.TenantID[18] == '-' && c.TenantID[23] == '-' {
		return c
	}
	resolved := claimsTenantResolver(ctx, c.TenantID)
	if resolved != "" {
		c.TenantID = resolved
	}
	return c
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

			// 2. Try Bearer JWT header (API clients / CI-CD path).
			// FIX 2026-05-07: an INVALID Bearer used to short-circuit with
			// 401 even when the request also carried a valid vsp_token
			// cookie. That broke iframe panels whose inline JS sets
			// `Authorization: Bearer ${stale_localStorage_token}` faster
			// than the bootstrap handshake refreshes localStorage. Now we
			// log the parse failure but FALL THROUGH to the cookie check —
			// the request is still rejected at step 4 if every source fails.
			if !ok {
				bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				if bearer != "" {
					c, err := parseJWTWithRotation(bearer, resolveSecrets(jwtSecret))
					if err != nil {
						log.Warn().Str("ip", r.RemoteAddr).Err(err).Msg("invalid jwt header — trying cookie fallback")
					} else {
						claims, ok = c, true
					}
				}
			}

			// 3. Try httpOnly cookie (browser path — OWASP A07)
			if !ok {
				if cookie, err := r.Cookie("vsp_token"); err == nil && cookie.Value != "" {
					c, err := parseJWTWithRotation(cookie.Value, resolveSecrets(jwtSecret))
					if err != nil {
						log.Warn().Str("ip", r.RemoteAddr).Err(err).Msg("invalid cookie jwt")
					} else {
						claims, ok = c, true
					}
				}
			}

			if !ok {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}

			// L9 2026-05-09: canonicalise TenantID to UUID once here so
			// every downstream handler reads a UUID. Removes the burden
			// of resolveTenantUUID from each handler.
			claims = canonicalizeTenant(r.Context(), claims)
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
	// Alias fields — JWTs minted by older flows or external scripts
	// (scripts/mint_jwt*.sh) use the longer key names. Reading both
	// avoids 401s when the user's token in localStorage was issued by
	// one of those tools.
	UserIDAlt   string `json:"sub,omitempty"`
	TenantIDAlt string `json:"tenant_id,omitempty"`
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

// RevokeCurrentToken adds a JTI to the blacklist. Called from Logout handler.
// Safe no-op if blacklist is not configured or JTI is empty.
func RevokeCurrentToken(ctx context.Context, jti string, expiresAt time.Time) {
	if globalBlacklist == nil || jti == "" {
		return
	}
	type revoker interface {
		Revoke(ctx context.Context, tokenID string, expiresAt time.Time) error
	}
	if r, ok := globalBlacklist.(revoker); ok {
		_ = r.Revoke(ctx, jti, expiresAt)
	}
}

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
	// Coalesce alias fields: prefer the canonical key but fall back to
	// the long-form keys some legacy mint flows emit.
	uid := c.UserID
	if uid == "" {
		uid = c.UserIDAlt
	}
	tid := c.TenantID
	if tid == "" {
		tid = c.TenantIDAlt
	}
	out := Claims{
		UserID:   uid,
		TenantID: tid,
		Role:     c.Role,
		Email:    c.Email,
		JTI:      c.ID,
	}
	if c.ExpiresAt != nil {
		out.ExpiresAt = c.ExpiresAt.Time
	}
	return out, nil
}

func injectClaims(ctx context.Context, c Claims) context.Context {
	ctx = context.WithValue(ctx, CtxUserID, c.UserID)
	ctx = context.WithValue(ctx, CtxTenantID, c.TenantID)
	ctx = context.WithValue(ctx, CtxRole, c.Role)
	ctx = context.WithValue(ctx, CtxJTI, c.JTI)
	ctx = context.WithValue(ctx, CtxExpiresAt, c.ExpiresAt)
	ctx = context.WithValue(ctx, CtxEmail, c.Email)
	return ctx
}

// InjectForTest injects Claims into context for use in unit tests.
// Do NOT use in production code.
func InjectForTest(ctx context.Context, c Claims) context.Context {
	return injectClaims(ctx, c)
}
