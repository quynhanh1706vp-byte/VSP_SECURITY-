package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OIDCConfig holds configuration for an OIDC/OAuth2 provider.
type OIDCConfig struct {
	Enabled      bool   `yaml:"enabled"`
	ProviderName string `yaml:"provider_name"` // google, azure, okta, keycloak, github
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURL  string `yaml:"redirect_url"`
	// OIDC discovery or manual endpoints
	AuthURL      string `yaml:"auth_url"`
	TokenURL     string `yaml:"token_url"`
	UserInfoURL  string `yaml:"userinfo_url"`
	Scopes       []string `yaml:"scopes"`
	// Role mapping
	DefaultRole  string `yaml:"default_role"` // analyst / admin
	AdminDomains []string `yaml:"admin_domains"` // e.g. ["company.com"]
}

// Well-known provider presets
var ProviderPresets = map[string]OIDCConfig{
	"google": {
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:    "https://oauth2.googleapis.com/token",
		UserInfoURL: "https://www.googleapis.com/oauth2/v3/userinfo",
		Scopes:      []string{"openid", "email", "profile"},
	},
	"github": {
		AuthURL:     "https://github.com/login/oauth/authorize",
		TokenURL:    "https://github.com/login/oauth/access_token",
		UserInfoURL: "https://api.github.com/user",
		Scopes:      []string{"read:user", "user:email"},
	},
	"azure": {
		// Tenant ID must be injected: replace {tenant} in URLs
		AuthURL:     "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
		TokenURL:    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
		UserInfoURL: "https://graph.microsoft.com/oidc/userinfo",
		Scopes:      []string{"openid", "email", "profile"},
	},
	"okta": {
		// Domain must be injected: replace {domain}
		AuthURL:     "https://{domain}/oauth2/default/v1/authorize",
		TokenURL:    "https://{domain}/oauth2/default/v1/token",
		UserInfoURL: "https://{domain}/oauth2/default/v1/userinfo",
		Scopes:      []string{"openid", "email", "profile"},
	},
}

// OIDCHandler manages OAuth2 flows.
type OIDCHandler struct {
	Config    OIDCConfig
	JWTSecret string
	JWTTTL    time.Duration
	DB        interface {
		FindOrCreateSSOUser(ctx context.Context, email, name, provider, sub, role string) (userID, tenantID string, err error)
	}
}

// GenerateState creates a random state token for CSRF protection.
func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil { return "", err }
	return base64.URLEncoding.EncodeToString(b), nil
}

// AuthCodeURL returns the provider's authorization URL.
func (h *OIDCHandler) AuthCodeURL(state string) string {
	params := url.Values{
		"client_id":     {h.Config.ClientID},
		"redirect_uri":  {h.Config.RedirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(h.Config.Scopes, " ")},
		"state":         {state},
	}
	return h.Config.AuthURL + "?" + params.Encode()
}

// ExchangeCode exchanges an auth code for tokens.
func (h *OIDCHandler) ExchangeCode(ctx context.Context, code string) (accessToken string, err error) {
	data := url.Values{
		"client_id":     {h.Config.ClientID},
		"client_secret": {h.Config.ClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {h.Config.RedirectURL},
	}
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, "POST", h.Config.TokenURL,
		strings.NewReader(data.Encode()))
	if err != nil { return }
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return }
	if resp == nil { return }
	defer resp.Body.Close()

	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&tok); err != nil { return }
	if tok.Error != "" { err = fmt.Errorf("oauth2: %s", tok.Error); return }
	accessToken = tok.AccessToken
	return
}

// UserInfo fetches user info from the provider.
type UserInfo struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Login string `json:"login"` // GitHub
}

func (h *OIDCHandler) FetchUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", h.Config.UserInfoURL, nil)
	if err != nil { return nil, err }
	req.Header.Set("Authorization", "Bearer " + accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	if resp == nil { return nil, fmt.Errorf("oidc: empty response") }
	defer resp.Body.Close()

	var info UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil { return nil, err }
	// GitHub uses login as name
	if info.Name == "" && info.Login != "" { info.Name = info.Login }
	if info.Sub == "" { info.Sub = info.Email }
	return &info, nil
}

// DetermineRole returns admin if email domain is in admin_domains list.
func (h *OIDCHandler) DetermineRole(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		domain := parts[1]
		for _, d := range h.Config.AdminDomains {
			if d == domain { return "admin" }
		}
	}
	if h.Config.DefaultRole != "" { return h.Config.DefaultRole }
	return "analyst"
}
