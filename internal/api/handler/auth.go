package handler

import (
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
}

type loginResponse struct {
	Token    string `json:"token"`
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	TenantID string `json:"tenant_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" || req.Password == "" {
		jsonError(w, "email and password required", http.StatusBadRequest)
		return
	}

	// Resolve tenant — use default for now; extend with X-Tenant-Slug header later
	tenantID := a.DefaultTID

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

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PwHash), []byte(req.Password)); err != nil {
		// Log but return same message to prevent user enumeration
		log.Warn().Str("email", req.Email).Msg("login: wrong password")
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

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
	go a.writeAudit(r, tenantID, &user.ID, "LOGIN_OK", "/auth/login")

	jsonOK(w, loginResponse{
		Token:     token,
		UserID:    user.ID,
		Email:     user.Email,
		Role:      user.Role,
		TenantID:  user.TenantID,
		ExpiresAt: time.Now().Add(ttl),
	})
}

// ── POST /api/v1/auth/logout ──────────────────────────────────────────────────
// Stateless JWT — logout is client-side token discard.
// We log the event for audit purposes.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if ok {
		go a.writeAudit(r, claims.TenantID, &claims.UserID, "LOGOUT", "/auth/logout")
	}
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
	a.DB.InsertAudit(r.Context(), tenantID, userID, action, resource, r.RemoteAddr, nil, e.StoredHash, prevHash) //nolint:errcheck
}

func derefStr(s *string) string {
	if s == nil { return "" }
	return *s
}
