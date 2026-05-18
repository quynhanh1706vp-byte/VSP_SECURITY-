// SSO OIDC handler — implements the previously-stubbed endpoints.
// Phase 4.5.3 · April 2026
package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/sso"
	"github.com/vsp/platform/internal/store"
)

type SSOOIDCHandler struct {
	StoreDB   *store.DB
	DB        *sql.DB
	JWTSecret string
	JWTTTL    time.Duration
	IssueJWT  func(secret string, claims auth.Claims, ttl time.Duration) (string, error)
}

func NewSSOOIDCHandler(db *sql.DB, secret string, ttl time.Duration,
	issueFn func(string, auth.Claims, time.Duration) (string, error)) *SSOOIDCHandler {
	return &SSOOIDCHandler{DB: db, JWTSecret: secret, JWTTTL: ttl, IssueJWT: issueFn}
}

// providerRequest is used for POST/PUT/PATCH to allow client_secret input.
// sso.Provider has ClientSecret json:"-" to prevent leaking in GET responses,
// so we use this wrapper for write operations only.
type providerRequest struct {
	sso.Provider
	ClientSecretInput string `json:"client_secret"`
}

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
		var req providerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		p := req.Provider
		if req.ClientSecretInput != "" {
			p.ClientSecret = req.ClientSecretInput
		}
		p.TenantID = tenantID
		if p.Type == "" {
			p.Type = "oidc"
		}
		if msg := validateProvider(p); msg != "" {
			writeJSON2(w, http.StatusUnprocessableEntity, map[string]string{"error": msg})
			return
		}
		id, err := sso.CreateProvider(r.Context(), h.DB, p)
		if err != nil {
			writeJSON2(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		h.auditSSO(r, "SSO_PROVIDER_CREATED", fmt.Sprintf("sso/providers/%d", id))
		writeJSON2(w, http.StatusCreated, map[string]any{"id": id})
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSON2(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *SSOOIDCHandler) ProviderByID(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantStr(r)
	if !ok {
		writeJSON2(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	id, err := parseIDParam(r)
	if err != nil {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		p, err := sso.GetProvider(r.Context(), h.DB, id)
		if err != nil {
			if err == sql.ErrNoRows {
				writeJSON2(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON2(w, http.StatusOK, p)
	case http.MethodPut:
		var req providerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		p := req.Provider
		if req.ClientSecretInput != "" {
			p.ClientSecret = req.ClientSecretInput
		}
		p.ID = id
		p.TenantID = tenantID
		if msg := validateProvider(p); msg != "" {
			writeJSON2(w, http.StatusUnprocessableEntity, map[string]string{"error": msg})
			return
		}
		if err := sso.UpdateProvider(r.Context(), h.DB, p); err != nil {
			if err == sql.ErrNoRows {
				writeJSON2(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			writeJSON2(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON2(w, http.StatusOK, map[string]string{"status": "updated"})
	case http.MethodPatch:
		existing, err := sso.GetProvider(r.Context(), h.DB, id)
		if err != nil {
			if err == sql.ErrNoRows {
				writeJSON2(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if existing.TenantID != tenantID {
			writeJSON2(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if err := json.NewDecoder(r.Body).Decode(existing); err != nil {
			writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		existing.ID = id
		existing.TenantID = tenantID
		if msg := validateProvider(*existing); msg != "" {
			writeJSON2(w, http.StatusUnprocessableEntity, map[string]string{"error": msg})
			return
		}
		if err := sso.UpdateProvider(r.Context(), h.DB, *existing); err != nil {
			writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		h.auditSSO(r, "SSO_PROVIDER_DELETED", fmt.Sprintf("sso/providers/%d", id))
		writeJSON2(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		w.Header().Set("Allow", "GET, PUT, PATCH, DELETE")
		writeJSON2(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

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
	if p.RedirectURI == "" {
		writeJSON2(w, http.StatusUnprocessableEntity, map[string]string{
			"error": "provider redirect_uri not configured — edit provider first",
		})
		return
	}
	if p.ClientID == "" || p.IssuerURL == "" {
		writeJSON2(w, http.StatusUnprocessableEntity, map[string]string{
			"error": "provider configuration incomplete",
		})
		return
	}
	disc, err := sso.FetchDiscovery(r.Context(), h.DB, p)
	if err != nil {
		writeJSON2(w, http.StatusBadGateway, map[string]string{"error": "discovery failed: " + err.Error()})
		return
	}
	redirAfter := safeRedirectPath(r.URL.Query().Get("redirect"))
	ls, err := sso.CreateLoginState(r.Context(), h.DB, p.ID, redirAfter)
	if err != nil {
		writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	authzURL := sso.AuthorizeURL(disc, p, ls)
	// #nosec G710 nosemgrep: go.lang.security.injection.open-redirect.open-redirect
	http.Redirect(w, r, authzURL, http.StatusFound)
}

func (h *SSOOIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON2(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		writeJSON2(w, http.StatusBadRequest, map[string]string{
			"error": errCode, "error_description": q.Get("error_description"),
		})
		return
	}
	code, state := q.Get("code"), q.Get("state")
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
	claims, err := sso.VerifyIDToken(r.Context(), tokens.IDToken, disc.JWKSURI, p.IssuerURL, p.ClientID)
	if err != nil {
		writeJSON2(w, http.StatusUnauthorized, map[string]string{"error": "id_token verify: " + err.Error()})
		return
	}
	if err := sso.ValidateClaims(claims, p, ls.Nonce); err != nil {
		writeJSON2(w, http.StatusUnauthorized, map[string]string{"error": "id_token invalid: " + err.Error()})
		return
	}
	if len(p.AllowedDomains) > 0 {
		allowed := false
		emailLower := strings.ToLower(claims.Email)
		for _, dom := range p.AllowedDomains {
			if strings.HasSuffix(emailLower, "@"+strings.ToLower(dom)) {
				allowed = true
				break
			}
		}
		if !allowed {
			writeJSON2(w, http.StatusForbidden, map[string]string{"error": "email domain not allowed"})
			return
		}
	}
	userID, role, err := h.resolveOrProvisionUser(r.Context(), p.TenantID, claims.Email, claims.Name, p.DefaultRole)
	if err != nil {
		writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": "user provision: " + err.Error()})
		return
	}
	token, err := h.IssueJWT(h.JWTSecret, auth.Claims{
		UserID: userID, TenantID: p.TenantID, Role: role, Email: claims.Email,
	}, h.JWTTTL)
	if err != nil {
		writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": "jwt issue: " + err.Error()})
		return
	}
	// Audit SSO login — required for AnomalyDetector (scans LOGIN_SSO_OK)
	// and compliance: NIST 800-53 AU-2, FedRAMP AC-17, SOC2 CC6.1.
	h.auditSSO(r, "LOGIN_SSO_OK", "sso/provider/"+p.Name+"/user/"+claims.Email)
	// #nosec G124
	http.SetCookie(w, &http.Cookie{
		Name: "vsp_token", Value: token, Path: "/", HttpOnly: true,
		Secure:   r.TLS != nil || strings.HasPrefix(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.JWTTTL.Seconds()),
	})
	// #nosec G710 nosemgrep: go.lang.security.injection.open-redirect.open-redirect
	http.Redirect(w, r, safeRedirectPath(ls.RedirectAfter), http.StatusFound)
}

func (h *SSOOIDCHandler) TestProvider(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantStr(r)
	if !ok {
		writeJSON2(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	id, err := parseIDParam(r)
	if err != nil {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	p, err := sso.GetProvider(r.Context(), h.DB, id)
	if err != nil || p.TenantID != tenantID {
		writeJSON2(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	start := time.Now()
	_, discErr := sso.FetchDiscoveryFresh(r.Context(), h.DB, p)
	latency := time.Since(start).Milliseconds()
	if discErr != nil {
		writeJSON2(w, http.StatusOK, map[string]any{
			"ok": false, "latency_ms": latency,
			"error": discErr.Error(), "issuer_url": p.IssuerURL,
		})
		return
	}
	writeJSON2(w, http.StatusOK, map[string]any{
		"ok": true, "latency_ms": latency,
		"issuer_url": p.IssuerURL, "provider": p.Name,
	})
}

func (h *SSOOIDCHandler) ToggleProvider(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantStr(r)
	if !ok {
		writeJSON2(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	id, err := parseIDParam(r)
	if err != nil {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Enabled {
		p, err := sso.GetProvider(r.Context(), h.DB, id)
		if err != nil {
			if err == sql.ErrNoRows {
				writeJSON2(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if p.TenantID != tenantID {
			writeJSON2(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if msg := validateProvider(*p); msg != "" {
			writeJSON2(w, http.StatusUnprocessableEntity, map[string]string{
				"error": "cannot enable: " + msg,
			})
			return
		}
	}
	res, err := h.DB.ExecContext(r.Context(),
		"UPDATE sso_providers SET enabled=$1, updated_at=now() WHERE id=$2 AND tenant_id=$3",
		req.Enabled, id, tenantID)
	if err != nil {
		writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON2(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON2(w, http.StatusOK, map[string]any{"id": id, "enabled": req.Enabled})
}

func safeRedirectPath(p string) string {
	if p == "" || p[0] != '/' {
		return "/"
	}
	if len(p) >= 2 && p[1] == '/' {
		return "/"
	}
	if strings.Contains(p, `\`) {
		return "/"
	}
	return p
}

func (h *SSOOIDCHandler) resolveOrProvisionUser(ctx context.Context,
	tenantID, email, name, defaultRole string) (string, string, error) {
	var userID, role string
	err := h.DB.QueryRowContext(ctx,
		`SELECT id::text, role FROM users WHERE tenant_id = $1::uuid AND email = $2`,
		tenantID, email).Scan(&userID, &role)
	if err == nil {
		return userID, role, nil
	}
	if err != sql.ErrNoRows {
		return "", "", err
	}
	if defaultRole == "" {
		defaultRole = "analyst"
	}
	// Sentinel pw_hash "!" — convention from /etc/shadow for locked accounts.
	// bcrypt hashes always start with "$2", so this can never match.
	err = h.DB.QueryRowContext(ctx, `
		INSERT INTO users (tenant_id, email, pw_hash, role)
		VALUES ($1::uuid, $2, '!sso-only-account', $3)
		ON CONFLICT (tenant_id, email) DO UPDATE SET role = EXCLUDED.role
		RETURNING id::text, role
	`, tenantID, email, defaultRole).Scan(&userID, &role)
	if err != nil {
		return "", "", fmt.Errorf("provision: %w", err)
	}
	return userID, role, nil
}

func validateProvider(p sso.Provider) string {
	if p.Name == "" {
		return "name is required"
	}
	if p.IssuerURL == "" {
		return "issuer_url is required"
	}
	if p.ClientID == "" {
		return "client_id is required"
	}
	if p.RedirectURI == "" {
		return "redirect_uri is required"
	}
	if _, err := url.ParseRequestURI(p.IssuerURL); err != nil {
		return "issuer_url must be a valid absolute URL"
	}
	if _, err := url.ParseRequestURI(p.RedirectURI); err != nil {
		return "redirect_uri must be a valid absolute URL"
	}
	placeholders := []string{
		"YOUR-TENANT-ID", "YOUR_TENANT_ID",
		"YOUR-ORG", "YOUR_ORG",
		"YOUR-REALM", "YOUR_REALM",
		"YOUR-TENANT.auth0",
		"example.com/oauth2/default",
		"tenant.b2clogin.com",
	}
	for _, ph := range placeholders {
		if strings.Contains(p.IssuerURL, ph) {
			return "issuer_url still contains placeholder " + ph + " — fill in your real tenant/org id before saving"
		}
		if strings.Contains(p.ClientID, ph) {
			return "client_id still contains placeholder " + ph
		}
		if strings.Contains(p.ClientSecret, ph) {
			return "client_secret still contains placeholder " + ph
		}
	}
	return ""
}

func parseIDParam(r *http.Request) (int64, error) {
	return strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
}

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

// ─── audit support ───────────────────────────────────────────────────

// SetAuditDB injects the store.DB needed for audit logging.
// Call after NewSSOOIDCHandler, same pattern as AIAdvisorHandler.
func (h *SSOOIDCHandler) SetAuditDB(db *store.DB) {
	h.StoreDB = db
}

func (h *SSOOIDCHandler) auditSSO(r *http.Request, action, resource string) {
	if h.StoreDB == nil {
		return
	}
	logAudit(r, h.StoreDB, action, resource)
}

// RotateSecret: PATCH /api/v1/sso/providers/{id}/rotate-secret
// Rotates client_secret with 5-minute grace period for in-flight exchanges.
// The old secret is kept in client_secret_prev during the grace window.
func (h *SSOOIDCHandler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantStr(r)
	if !ok {
		writeJSON2(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	id, err := parseIDParam(r)
	if err != nil {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req struct {
		NewSecret string `json:"new_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NewSecret == "" {
		writeJSON2(w, http.StatusBadRequest, map[string]string{"error": "new_secret required"})
		return
	}
	if err := sso.RotateSecret(r.Context(), h.DB, id, tenantID, req.NewSecret); err != nil {
		if err == sql.ErrNoRows {
			writeJSON2(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON2(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Audit — secret rotation is a security-sensitive event (SOC2 CC6.1).
	h.auditSSO(r, "SSO_SECRET_ROTATED", fmt.Sprintf("sso/providers/%d", id))
	// Schedule grace-period commit after 5 minutes.
	go func() {
		time.Sleep(5 * time.Minute)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = sso.CommitRotation(ctx, h.DB, id, tenantID)
	}()
	writeJSON2(w, http.StatusOK, map[string]any{
		"status":       "rotated",
		"grace_period": "5m — old secret still valid during this window",
	})
}
