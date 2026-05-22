// Package sso implements OIDC and SAML authentication providers for VSP.
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

type Provider struct {
	ID             int64    `json:"id"`
	TenantID       string   `json:"tenant_id"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	IssuerURL      string   `json:"issuer_url"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"-"`
	RedirectURI    string   `json:"redirect_uri"`
	Scopes         string   `json:"scopes"`
	Enabled        bool     `json:"enabled"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	DefaultRole    string   `json:"default_role"`
}

type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
}

type IDTokenClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   any    `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

const discoveryCacheTTL = 24 * time.Hour

func FetchDiscovery(ctx context.Context, db *sql.DB, p *Provider) (*Discovery, error) {
	var jsonBytes []byte
	var when sql.NullTime
	_ = db.QueryRowContext(ctx,
		`SELECT discovery_json, discovery_at FROM sso_providers WHERE id = $1`, p.ID,
	).Scan(&jsonBytes, &when)

	if when.Valid && len(jsonBytes) > 0 && time.Since(when.Time) < discoveryCacheTTL {
		var d Discovery
		if err := json.Unmarshal(jsonBytes, &d); err == nil &&
			d.AuthorizationEndpoint != "" && d.TokenEndpoint != "" {
			return &d, nil
		}
	}
	return fetchAndCacheDiscovery(ctx, db, p)
}

func FetchDiscoveryFresh(ctx context.Context, db *sql.DB, p *Provider) (*Discovery, error) {
	return fetchAndCacheDiscovery(ctx, db, p)
}

func fetchAndCacheDiscovery(ctx context.Context, db *sql.DB, p *Provider) (*Discovery, error) {
	disc, err := fetchDiscoveryHTTP(ctx, p.IssuerURL)
	if err != nil {
		return nil, err
	}
	dj, _ := json.Marshal(disc)
	_, _ = db.ExecContext(ctx,
		`UPDATE sso_providers SET discovery_json=$1, discovery_at=now() WHERE id=$2`, dj, p.ID)
	return disc, nil
}

func fetchDiscoveryHTTP(ctx context.Context, issuer string) (*Discovery, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: %s returned %d", u, resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		return nil, fmt.Errorf("discovery: %s returned content-type %q instead of application/json — verify issuer_url", u, ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("discovery: malformed JSON from %s: %w", u, err)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery: incomplete document at %s (missing authorization_endpoint or token_endpoint)", u)
	}
	if d.JWKSURI == "" {
		return nil, fmt.Errorf("discovery: incomplete document at %s (missing jwks_uri)", u)
	}
	return &d, nil
}

type LoginState struct {
	State         string
	ProviderID    int64
	Nonce         string
	PKCEVerifier  string
	RedirectAfter string
}

func CreateLoginState(ctx context.Context, db *sql.DB, providerID int64, redirectAfter string) (*LoginState, error) {
	state := randURLSafe(32)
	nonce := randURLSafe(32)
	verifier := randURLSafe(48)
	_, err := db.ExecContext(ctx,
		`INSERT INTO sso_login_states (state, provider_id, nonce, pkce_verifier, redirect_after)
		 VALUES ($1, $2, $3, $4, $5)`,
		state, providerID, nonce, verifier, nullStr(redirectAfter))
	if err != nil {
		return nil, err
	}
	return &LoginState{State: state, ProviderID: providerID, Nonce: nonce,
		PKCEVerifier: verifier, RedirectAfter: redirectAfter}, nil
}

func ConsumeLoginState(ctx context.Context, db *sql.DB, state string) (*LoginState, error) {
	var ls LoginState
	var redirAfter sql.NullString
	err := db.QueryRowContext(ctx, `
		DELETE FROM sso_login_states
		WHERE state=$1 AND expires_at > now()
		RETURNING state, provider_id, nonce, pkce_verifier, redirect_after`,
		state).Scan(&ls.State, &ls.ProviderID, &ls.Nonce, &ls.PKCEVerifier, &redirAfter)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("login state not found or expired")
	}
	if err != nil {
		return nil, err
	}
	ls.RedirectAfter = redirAfter.String
	return &ls, nil
}

func AuthorizeURL(disc *Discovery, p *Provider, ls *LoginState) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("scope", scopesOrDefault(p.Scopes))
	q.Set("state", ls.State)
	q.Set("nonce", ls.Nonce)
	q.Set("code_challenge", pkceChallenge(ls.PKCEVerifier))
	q.Set("code_challenge_method", "S256")
	return disc.AuthorizationEndpoint + "?" + q.Encode()
}

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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.TokenEndpoint, strings.NewReader(form.Encode()))
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
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		return nil, fmt.Errorf("token endpoint returned content-type %q — expected application/json", ct)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("token response parse: %w", err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("token endpoint error %q: %s", tr.Error, tr.ErrorDesc)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("no id_token in token response")
	}
	return &tr, nil
}

func ParseIDToken(idToken string) (*IDTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed id_token: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		padded := parts[1] + strings.Repeat("=", (4-len(parts[1])%4)%4)
		payload, err = base64.URLEncoding.DecodeString(padded)
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

func ValidateClaims(c *IDTokenClaims, p *Provider, expectedNonce string) error {
	if c.Exp < time.Now().Unix() {
		return fmt.Errorf("id_token expired (exp=%d)", c.Exp)
	}
	if strings.TrimRight(c.Iss, "/") != strings.TrimRight(p.IssuerURL, "/") {
		return fmt.Errorf("issuer mismatch: token=%q provider=%q", c.Iss, p.IssuerURL)
	}
	if !audMatches(c.Aud, p.ClientID) {
		return fmt.Errorf("audience mismatch: token=%v expected=%q", c.Aud, p.ClientID)
	}
	if c.Nonce != expectedNonce {
		return fmt.Errorf("nonce mismatch — possible replay attack")
	}
	if c.Email == "" {
		return fmt.Errorf("id_token missing email claim — enable email scope")
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

func scopesOrDefault(scopes string) string {
	if strings.TrimSpace(scopes) == "" {
		return "openid email profile"
	}
	return scopes
}

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
