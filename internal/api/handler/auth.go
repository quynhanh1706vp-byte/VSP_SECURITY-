package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/audit"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Auth bundles dependencies for auth handlers.
type Auth struct {
	DB         *store.DB
	JWTSecret  string
	JWTTTL     time.Duration
	DefaultTID string // default tenant for single-tenant dev setup
}

// ── POST /api/v1/auth/login ───────────────────────────────────────────────────

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"` // TOTP code nếu MFA enabled
}

type loginResponse struct {
	Token      string    `json:"token"`
	UserID     string    `json:"user_id"`
	Email      string    `json:"email"`
	Role       string    `json:"role"`
	TenantID   string    `json:"tenant_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	MFAEnabled bool      `json:"mfa_enabled"`
}

type mfaRequiredResponse struct {
	MFARequired bool   `json:"mfa_required"`
	Message     string `json:"message"`
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" || req.Password == "" {
		jsonError(w, "email and password required", http.StatusBadRequest)
		return
	}

	// Resolve tenant — X-Tenant-Slug header takes priority, fallback to default
	tenantID := a.DefaultTID
	if slug := strings.TrimSpace(r.Header.Get("X-Tenant-Slug")); slug != "" {
		var tid string
		a.DB.Pool().QueryRow(r.Context(),
			`SELECT id FROM tenants WHERE slug=$1 AND active=true LIMIT 1`, slug,
		).Scan(&tid) //nolint:errcheck
		if tid != "" {
			tenantID = tid
		}
	}

	// Lookup user
	user, err := a.DB.GetUserByEmail(r.Context(), tenantID, req.Email)
	if err != nil {
		log.Error().Err(err).Str("email", req.Email).Msg("login: db error")
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Check account lockout
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		log.Warn().Str("email", req.Email).Msg("login: account locked")
		go a.writeAudit(r.Clone(context.Background()), tenantID, &user.ID, "LOGIN_LOCKED", "/auth/login")
		jsonError(w, "account temporarily locked — too many failed attempts", http.StatusTooManyRequests)
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PwHash), []byte(req.Password)); err != nil {
		log.Warn().Msg("login: wrong password") // email not logged to prevent user enumeration
		// Record failed login + possible lockout
		count, _ := a.DB.RecordFailedLogin(r.Context(), user.ID)
		go a.writeAudit(r.Clone(context.Background()), tenantID, &user.ID, "LOGIN_FAILED", "/auth/login")
		if count >= 5 {
			jsonError(w, "account locked for 15 minutes after too many failed attempts", http.StatusTooManyRequests)
		} else {
			jsonError(w, "invalid credentials", http.StatusUnauthorized)
		}
		return
	}

	// Verify MFA if enabled
	if user.MFAEnabled && user.MFAVerified {
		if req.MFACode == "" {
			// Trả về mfa_required để frontend hiển thị form nhập code
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(mfaRequiredResponse{
				MFARequired: true,
				Message:     "MFA code required",
			})
			return
		}
		if !auth.VerifyTOTP(user.MFASecret, req.MFACode) {
			log.Warn().Str("email", req.Email).Msg("login: invalid MFA code")
			go a.writeAudit(r.Clone(context.Background()), tenantID, &user.ID, "LOGIN_MFA_FAILED", "/auth/login")
			jsonError(w, "invalid MFA code", http.StatusUnauthorized)
			return
		}
	}

	// Reset failed logins on success
	go a.DB.ResetFailedLogins(r.Context(), user.ID)

	// Issue JWT
	ttl := a.JWTTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	claims := auth.Claims{
		UserID:   user.ID,
		TenantID: user.TenantID,
		Role:     user.Role,
		Email:    user.Email,
	}
	token, err := auth.IssueJWT(a.JWTSecret, claims, ttl)
	if err != nil {
		log.Error().Err(err).Msg("login: issue jwt")
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Update last_login (best-effort)
	go a.DB.UpdateLastLogin(r.Context(), user.ID) //nolint:errcheck

	// Write audit log (best-effort)
	go a.writeAudit(r.Clone(context.Background()), tenantID, &user.ID, "LOGIN_OK", "/auth/login")

	// Set httpOnly cookie for browser clients (OWASP A07 — prevents XSS token theft)
	// API clients / CI-CD still get token in response body for Authorization: Bearer usage
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     "vsp_token",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,                    // JS cannot read — XSS cannot steal
		Secure:   secure,                  // HTTPS only in prod
		SameSite: http.SameSiteStrictMode, // CSRF protection
	})

	jsonOK(w, loginResponse{
		Token:      token, // kept for API clients / CI-CD
		UserID:     user.ID,
		Email:      user.Email,
		Role:       user.Role,
		TenantID:   user.TenantID,
		ExpiresAt:  time.Now().Add(ttl),
		MFAEnabled: user.MFAEnabled,
	})
}

// ── POST /api/v1/auth/logout ──────────────────────────────────────────────────
// Stateless JWT — logout is client-side token discard.
// We log the event for audit purposes.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if ok {
		go a.writeAudit(r.Clone(context.Background()), claims.TenantID, &claims.UserID, "LOGOUT", "/auth/logout")
	}
	// Clear httpOnly cookie on logout
	http.SetCookie(w, &http.Cookie{
		Name:     "vsp_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteStrictMode,
	})
	jsonOK(w, map[string]string{"message": "logged out"})
}

// ── POST /api/v1/auth/refresh ─────────────────────────────────────────────────
func (a *Auth) Refresh(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ttl := a.JWTTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	token, err := auth.IssueJWT(a.JWTSecret, claims, ttl)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"token":      token,
		"expires_at": time.Now().Add(ttl),
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (a *Auth) writeAudit(r *http.Request, tenantID string, userID *string, action, resource string) {
	prevHash, _ := a.DB.GetLastAuditHash(r.Context(), tenantID)
	e := audit.Entry{
		TenantID: tenantID,
		UserID:   derefStr(userID),
		Action:   action,
		Resource: resource,
		IP:       r.RemoteAddr,
		PrevHash: prevHash,
	}
	e.StoredHash = audit.Hash(e)
	a.DB.InsertAudit(r.Context(), store.AuditWriteParams{TenantID: tenantID, UserID: userID, Action: action, Resource: resource, IP: r.RemoteAddr, PrevHash: prevHash}) //nolint:errcheck
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ── GET /api/v1/auth/check ────────────────────────────────────────────────────
// Returns 200 if session is valid (cookie or Bearer), 401 if not.
// Used by frontend to skip login overlay when session exists.
func (a *Auth) Check(w http.ResponseWriter, r *http.Request) {
	_, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, `{"authenticated":false}`, http.StatusUnauthorized)
		return
	}
	jsonOK(w, map[string]bool{"authenticated": true})
}
