// SSO OIDC handler — implements the previously-stubbed endpoints.
// Phase 4.5.3 · April 2026
package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/sso"
)

// SSOOIDCHandler exposes the OIDC SSO REST + auth endpoints.
type SSOOIDCHandler struct {
	DB         *sql.DB
	JWTSecret  string
	JWTTTL     time.Duration
	IssueJWT   func(secret string, claims auth.Claims, ttl time.Duration) (string, error)
}

// NewSSOOIDCHandler constructs the handler. issueJWT comes from internal/auth.
func NewSSOOIDCHandler(db *sql.DB, secret string, ttl time.Duration,
	issueFn func(string, auth.Claims, time.Duration) (string, error)) *SSOOIDCHandler {
	return &SSOOIDCHandler{
		DB:        db,
		JWTSecret: secret,
		JWTTTL:    ttl,
		IssueJWT:  issueFn,
	}
}

// ─── Provider CRUD (admin only) ─────────────────────────────────────

// Providers: GET list, POST create.
// Path: /api/v1/sso/providers
func (h *SSOOIDCHandler) Providers(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantStr(r)
	if !ok {
		writeJSON2(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		list, err := sso.ListProviders(r.Context(), h.DB, tenantID)
		if err != nil {
			writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON2(w, http.StatusOK, map[string]any{"providers": list, "count": len(list)})

	case http.MethodPost:
		var p sso.Provider
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		p.TenantID = tenantID
		if p.Type == "" {
			p.Type = "oidc"
		}
		id, err := sso.CreateProvider(r.Context(), h.DB, p)
		if err != nil {
			writeJSON2(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON2(w, http.StatusCreated, map[string]any{"id": id})

	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSON2(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// ProviderByID: PUT update, DELETE.
// Path: /api/v1/sso/providers/{id}
func (h *SSOOIDCHandler) ProviderByID(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantStr(r)
	if !ok {
		writeJSON2(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "bad path"})
		return
	}
	id, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		var p sso.Provider
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		p.ID = id
		p.TenantID = tenantID
		if err := sso.UpdateProvider(r.Context(), h.DB, p); err != nil {
			if err == sql.ErrNoRows {
				writeJSON2(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			writeJSON2(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON2(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
		if err := sso.DeleteProvider(r.Context(), h.DB, id, tenantID); err != nil {
			if err == sql.ErrNoRows {
				writeJSON2(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON2(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		w.Header().Set("Allow", "PUT, DELETE")
		writeJSON2(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// ─── Login flow (no auth required) ──────────────────────────────────

// Login: GET /api/v1/auth/sso/login?provider_id=N&redirect=/dashboard
// Redirects to IdP authorize endpoint.
func (h *SSOOIDCHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON2(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	pidStr := r.URL.Query().Get("provider_id")
	if pidStr == "" {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "provider_id required"})
		return
	}
	pid, err := strconv.ParseInt(pidStr, 10, 64)
	if err != nil {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid provider_id"})
		return
	}

	p, err := sso.GetProvider(r.Context(), h.DB, pid)
	if err != nil {
		writeJSON2(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	if !p.Enabled {
		writeJSON2(w, http.StatusForbidden, map[string]string{"error": "provider disabled"})
		return
	}

	disc, err := sso.FetchDiscovery(r.Context(), h.DB, p)
	if err != nil {
		writeJSON2(w, http.StatusBadGateway, map[string]string{"error": "discovery failed: " + err.Error()})
		return
	}

	redirAfter := r.URL.Query().Get("redirect")
	if redirAfter == "" {
		redirAfter = "/"
	}

	ls, err := sso.CreateLoginState(r.Context(), h.DB, p.ID, redirAfter)
	if err != nil {
		writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	authzURL := sso.AuthorizeURL(disc, p, ls)
	http.Redirect(w, r, authzURL, http.StatusFound)
}

// Callback: GET /api/v1/auth/sso/callback?code=...&state=...
// Exchanges code → tokens → resolves user → issues VSP JWT.
func (h *SSOOIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON2(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		desc := q.Get("error_description")
		writeJSON2(w, http.StatusBadRequest, map[string]string{
			"error":             errCode,
			"error_description": desc,
		})
		return
	}

	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "code and state required"})
		return
	}

	ls, err := sso.ConsumeLoginState(r.Context(), h.DB, state)
	if err != nil {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	p, err := sso.GetProvider(r.Context(), h.DB, ls.ProviderID)
	if err != nil {
		writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": "provider lookup failed"})
		return
	}

	disc, err := sso.FetchDiscovery(r.Context(), h.DB, p)
	if err != nil {
		writeJSON2(w, http.StatusBadGateway, map[string]string{"error": "discovery: " + err.Error()})
		return
	}

	tokens, err := sso.ExchangeCode(r.Context(), disc, p, ls, code)
	if err != nil {
		writeJSON2(w, http.StatusBadGateway, map[string]string{"error": "token exchange: " + err.Error()})
		return
	}

	claims, err := sso.ParseIDToken(tokens.IDToken)
	if err != nil {
		writeJSON2(w, http.StatusBadGateway, map[string]string{"error": "id_token parse: " + err.Error()})
		return
	}

	if err := sso.ValidateClaims(claims, p, ls.Nonce); err != nil {
		writeJSON2(w, http.StatusUnauthorized, map[string]string{"error": "id_token invalid: " + err.Error()})
		return
	}

	// Domain restriction
	if len(p.AllowedDomains) > 0 {
		ok := false
		for _, dom := range p.AllowedDomains {
			if strings.HasSuffix(strings.ToLower(claims.Email), "@"+strings.ToLower(dom)) {
				ok = true
				break
			}
		}
		if !ok {
			writeJSON2(w, http.StatusForbidden, map[string]string{"error": "email domain not allowed"})
			return
		}
	}

	// Resolve user — auto-provision if not exists
	userID, role, err := h.resolveOrProvisionUser(r.Context(), p.TenantID, claims.Email, claims.Name, p.DefaultRole)
	if err != nil {
		writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": "user provision: " + err.Error()})
		return
	}

	// Issue VSP JWT
	jwtClaims := auth.Claims{
		UserID:   userID,
		TenantID: p.TenantID,
		Role:     role,
		Email:    claims.Email,
	}
	token, err := h.IssueJWT(h.JWTSecret, jwtClaims, h.JWTTTL)
	if err != nil {
		writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": "jwt issue: " + err.Error()})
		return
	}

	// Set HttpOnly cookie + redirect
	http.SetCookie(w, &http.Cookie{
		Name:     "vsp_jwt",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.HasPrefix(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.JWTTTL.Seconds()),
	})

	redirAfter := ls.RedirectAfter
	if redirAfter == "" {
		redirAfter = "/"
	}
	http.Redirect(w, r, redirAfter, http.StatusFound)
}

// resolveOrProvisionUser finds the VSP user by email or auto-creates one.
// Returns (user_id, role, error).
func (h *SSOOIDCHandler) resolveOrProvisionUser(ctx context.Context,
	tenantID, email, name, defaultRole string) (string, string, error) {

	var userID, role string
	err := h.DB.QueryRowContext(ctx, `
		SELECT id::text, role FROM users
		WHERE tenant_id = $1::uuid AND email = $2
	`, tenantID, email).Scan(&userID, &role)
	if err == nil {
		return userID, role, nil
	}
	if err != sql.ErrNoRows {
		return "", "", err
	}

	// Auto-provision with a random password hash (user logs in via SSO only)
	err = h.DB.QueryRowContext(ctx, `
		INSERT INTO users (tenant_id, email, pw_hash, role)
		VALUES ($1::uuid, $2, $3, $4)
		RETURNING id::text, role
	`, tenantID, email, "$2b$12$ssoonlyaccountsdonotloginbypassword", defaultRole).Scan(&userID, &role)
	if err != nil {
		return "", "", fmt.Errorf("provision: %w", err)
	}
	return userID, role, nil
}

// ─── helpers ────────────────────────────────────────────────────────

func tenantStr(r *http.Request) (string, bool) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		return "", false
	}
	return claims.TenantID, true
}

func writeJSON2(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
