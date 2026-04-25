// Package sso implements OIDC and SAML authentication providers for VSP.
//
// Phase 4.5.3 ships OIDC. SAML support is scaffolded but disabled at runtime.
package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider represents a configured SSO provider for a tenant.
type Provider struct {
	ID             int64    `json:"id"`
	TenantID       string   `json:"tenant_id"`
	Name           string   `json:"name"`
	Type           string   `json:"type"` // "oidc" or "saml"
	IssuerURL      string   `json:"issuer_url"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"-"` // never marshaled to JSON
	RedirectURI    string   `json:"redirect_uri"`
	Scopes         string   `json:"scopes"`
	Enabled        bool     `json:"enabled"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	DefaultRole    string   `json:"default_role"`
}

// Discovery is the parsed /.well-known/openid-configuration response.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
}

// IDTokenClaims is the subset of OIDC ID token claims we use.
type IDTokenClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   any    `json:"aud"` // string OR []string per OIDC spec
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// FetchDiscovery loads (and caches in DB) the OIDC discovery document.
func FetchDiscovery(ctx context.Context, db *sql.DB, p *Provider) (*Discovery, error) {
	// Try cache (24h)
	var (
		jsonBytes []byte
		when      sql.NullTime
	)
	err := db.QueryRowContext(ctx, `
		SELECT discovery_json, discovery_at FROM sso_providers WHERE id = $1
	`, p.ID).Scan(&jsonBytes, &when)
	if err == nil && when.Valid && time.Since(when.Time) < 24*time.Hour && len(jsonBytes) > 0 {
		var d Discovery
		if err := json.Unmarshal(jsonBytes, &d); err == nil {
			return &d, nil
		}
	}

	// Fetch fresh
	disc, err := fetchDiscoveryHTTP(ctx, p.IssuerURL)
	if err != nil {
		return nil, err
	}

	// Cache it
	dj, _ := json.Marshal(disc)
	_, _ = db.ExecContext(ctx, `
		UPDATE sso_providers SET discovery_json = $1, discovery_at = now()
		WHERE id = $2
	`, dj, p.ID)

	return disc, nil
}

func fetchDiscoveryHTTP(ctx context.Context, issuer string) (*Discovery, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("discovery: %s returned %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery: incomplete document at %s", u)
	}
	return &d, nil
}

// LoginState holds transient state for an in-flight login request.
type LoginState struct {
	State         string
	ProviderID    int64
	Nonce         string
	PKCEVerifier  string
	RedirectAfter string
}

// CreateLoginState generates random state + nonce + PKCE pair and stores them.
func CreateLoginState(ctx context.Context, db *sql.DB, providerID int64, redirectAfter string) (*LoginState, error) {
	state := randURLSafe(32)
	nonce := randURLSafe(32)
	verifier := randURLSafe(48) // PKCE verifier 43-128 chars

	_, err := db.ExecContext(ctx, `
		INSERT INTO sso_login_states (state, provider_id, nonce, pkce_verifier, redirect_after)
		VALUES ($1, $2, $3, $4, $5)
	`, state, providerID, nonce, verifier, nullStr(redirectAfter))
	if err != nil {
		return nil, err
	}
	return &LoginState{State: state, ProviderID: providerID, Nonce: nonce,
		PKCEVerifier: verifier, RedirectAfter: redirectAfter}, nil
}

// ConsumeLoginState retrieves and deletes (single-use) a login state.
func ConsumeLoginState(ctx context.Context, db *sql.DB, state string) (*LoginState, error) {
	var ls LoginState
	var redirAfter sql.NullString
	err := db.QueryRowContext(ctx, `
		DELETE FROM sso_login_states
		WHERE state = $1 AND expires_at > now()
		RETURNING state, provider_id, nonce, pkce_verifier, redirect_after
	`, state).Scan(&ls.State, &ls.ProviderID, &ls.Nonce, &ls.PKCEVerifier, &redirAfter)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("state not found or expired")
	}
	if err != nil {
		return nil, err
	}
	ls.RedirectAfter = redirAfter.String
	return &ls, nil
}

// AuthorizeURL builds the IdP authorize URL with state, nonce, PKCE challenge.
func AuthorizeURL(disc *Discovery, p *Provider, ls *LoginState) string {
	challenge := pkceChallenge(ls.PKCEVerifier)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("scope", p.Scopes)
	q.Set("state", ls.State)
	q.Set("nonce", ls.Nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return disc.AuthorizationEndpoint + "?" + q.Encode()
}

// ExchangeCode swaps the authorization code for tokens.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

func ExchangeCode(ctx context.Context, disc *Discovery, p *Provider, ls *LoginState, code string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.RedirectURI)
	form.Set("client_id", p.ClientID)
	form.Set("client_secret", p.ClientSecret)
	form.Set("code_verifier", ls.PKCEVerifier)

	req, err := http.NewRequestWithContext(ctx, "POST", disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	cli := &http.Client{Timeout: 15 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("token response parse: %w (body: %s)", err, string(body))
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("token endpoint: %s: %s", tr.Error, tr.ErrorDesc)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("no id_token in response")
	}
	return &tr, nil
}

// ParseIDToken extracts claims WITHOUT signature verification.
//
// NOTE: For production, signature verification using the provider's JWKS
// is required. Phase 4.5.3 ships claim-extraction; signature verification
// is added in Phase 4.5.3b (defers since each provider's JWKS handling
// varies and adds ~150 lines for the JWKS cache + RSA/ECDSA verifiers).
//
// Mitigation: we still validate iss, aud, exp, nonce — and we only trust
// the token if it came back from the configured token endpoint over TLS.
func ParseIDToken(idToken string) (*IDTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some providers use base64 std, try with padding
		payload, err = base64.URLEncoding.DecodeString(parts[1] + strings.Repeat("=", (4-len(parts[1])%4)%4))
		if err != nil {
			return nil, fmt.Errorf("id_token payload decode: %w", err)
		}
	}
	var claims IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("id_token payload parse: %w", err)
	}
	return &claims, nil
}

// ValidateClaims runs the standard OIDC claim checks.
func ValidateClaims(c *IDTokenClaims, p *Provider, expectedNonce string) error {
	now := time.Now().Unix()
	if c.Exp < now {
		return fmt.Errorf("id_token expired (exp=%d, now=%d)", c.Exp, now)
	}
	// Issuer must match (allow trailing slash mismatch)
	cIss := strings.TrimRight(c.Iss, "/")
	pIss := strings.TrimRight(p.IssuerURL, "/")
	if cIss != pIss {
		return fmt.Errorf("issuer mismatch: %s != %s", c.Iss, p.IssuerURL)
	}
	// Audience must contain our client_id
	if !audMatches(c.Aud, p.ClientID) {
		return fmt.Errorf("audience mismatch: %v != %s", c.Aud, p.ClientID)
	}
	// Nonce must match
	if c.Nonce != expectedNonce {
		return fmt.Errorf("nonce mismatch")
	}
	if c.Email == "" {
		return fmt.Errorf("id_token missing email claim")
	}
	return nil
}

func audMatches(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

// ─── helpers ────────────────────────────────────────────────────

func randURLSafe(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
