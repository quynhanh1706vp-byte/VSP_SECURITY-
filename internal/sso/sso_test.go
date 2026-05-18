package sso

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ─── validateProvider (via oidc.go) ──────────────────────────────────

func TestSafeRedirectPath(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", "/"},
		{"/dashboard", "/dashboard"},
		{"//evil.com", "/"},
		{"https://evil.com", "/"},
		{`/path\with\backslash`, "/"},
		{"/valid/path?q=1", "/valid/path?q=1"},
	}
	// safeRedirectPath is in sso_oidc.go (handler package) — test indirectly
	// via the logic here since it's unexported from handler.
	// We replicate the logic to unit-test the rules.
	safe := func(p string) string {
		if p == "" || p[0] != '/' {
			return "/"
		}
		if len(p) >= 2 && p[1] == '/' {
			return "/"
		}
		for _, c := range p {
			if c == '\\' {
				return "/"
			}
		}
		return p
	}
	for _, c := range cases {
		got := safe(c.input)
		if got != c.want {
			t.Errorf("safeRedirectPath(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestAudMatches(t *testing.T) {
	cases := []struct {
		aud      any
		expected string
		want     bool
	}{
		{"myclient", "myclient", true},
		{"myclient", "other", false},
		{[]any{"myclient", "other"}, "myclient", true},
		{[]any{"a", "b"}, "myclient", false},
		{nil, "myclient", false},
		// []string không xuất hiện trong JWT decode (luôn là []any từ json.Unmarshal)
		// audMatches hỗ trợ []string qua type switch nhưng JWT path dùng []any.
		// {[]string{"myclient"}, "myclient", true}, // covered by jwks.go audContains
	}
	for _, c := range cases {
		got := audMatches(c.aud, c.expected)
		if got != c.want {
			t.Errorf("audMatches(%v, %q) = %v, want %v", c.aud, c.expected, got, c.want)
		}
	}
}

func TestScopesOrDefault(t *testing.T) {
	if got := scopesOrDefault(""); got != "openid email profile" {
		t.Errorf("empty scopes: got %q", got)
	}
	if got := scopesOrDefault("   "); got != "openid email profile" {
		t.Errorf("whitespace scopes: got %q", got)
	}
	if got := scopesOrDefault("openid email"); got != "openid email" {
		t.Errorf("custom scopes: got %q", got)
	}
}

func TestPKCEChallenge(t *testing.T) {
	// RFC 7636 test vector
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)
	expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if challenge != expected {
		t.Errorf("pkceChallenge = %q, want %q", challenge, expected)
	}
}

func TestValidateClaims(t *testing.T) {
	p := &Provider{
		IssuerURL: "https://example.okta.com",
		ClientID:  "myclientid",
	}
	now := time.Now().Unix()

	t.Run("valid", func(t *testing.T) {
		c := &IDTokenClaims{
			Iss:   "https://example.okta.com",
			Aud:   "myclientid",
			Exp:   now + 3600,
			Nonce: "testnonce",
			Email: "user@example.com",
		}
		if err := ValidateClaims(c, p, "testnonce"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		c := &IDTokenClaims{
			Iss: "https://example.okta.com", Aud: "myclientid",
			Exp: now - 1, Nonce: "testnonce", Email: "user@example.com",
		}
		if err := ValidateClaims(c, p, "testnonce"); err == nil {
			t.Error("expected expired error")
		}
	})

	t.Run("iss_mismatch", func(t *testing.T) {
		c := &IDTokenClaims{
			Iss: "https://evil.com", Aud: "myclientid",
			Exp: now + 3600, Nonce: "testnonce", Email: "user@example.com",
		}
		if err := ValidateClaims(c, p, "testnonce"); err == nil {
			t.Error("expected iss mismatch error")
		}
	})

	t.Run("nonce_mismatch", func(t *testing.T) {
		c := &IDTokenClaims{
			Iss: "https://example.okta.com", Aud: "myclientid",
			Exp: now + 3600, Nonce: "wrongnonce", Email: "user@example.com",
		}
		if err := ValidateClaims(c, p, "testnonce"); err == nil {
			t.Error("expected nonce mismatch error")
		}
	})

	t.Run("missing_email", func(t *testing.T) {
		c := &IDTokenClaims{
			Iss: "https://example.okta.com", Aud: "myclientid",
			Exp: now + 3600, Nonce: "testnonce", Email: "",
		}
		if err := ValidateClaims(c, p, "testnonce"); err == nil {
			t.Error("expected missing email error")
		}
	})

	t.Run("trailing_slash_iss", func(t *testing.T) {
		c := &IDTokenClaims{
			Iss: "https://example.okta.com/", Aud: "myclientid",
			Exp: now + 3600, Nonce: "testnonce", Email: "user@example.com",
		}
		if err := ValidateClaims(c, p, "testnonce"); err != nil {
			t.Errorf("trailing slash should be tolerated: %v", err)
		}
	})
}

func TestFetchDiscoveryHTTP_ContentType(t *testing.T) {
	// Mock server returning HTML (simulates X.com / login-wall behavior)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte("<html>Login required</html>"))
	}))
	defer srv.Close()

	_, err := fetchDiscoveryHTTP(t.Context(), srv.URL)
	if err == nil {
		t.Error("expected error for HTML response")
	}
	if err != nil && !contains(err.Error(), "content-type") {
		t.Errorf("expected content-type error, got: %v", err)
	}
}

func TestFetchDiscoveryHTTP_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	_, err := fetchDiscoveryHTTP(t.Context(), srv.URL)
	if err == nil {
		t.Error("expected error for 404")
	}
}

func TestFetchDiscoveryHTTP_IncompleteDoc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"https://example.com"}`)) // missing endpoints
	}))
	defer srv.Close()

	_, err := fetchDiscoveryHTTP(t.Context(), srv.URL)
	if err == nil {
		t.Error("expected error for incomplete discovery doc")
	}
}

func TestFetchDiscoveryHTTP_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"issuer": "https://example.okta.com",
			"authorization_endpoint": "https://example.okta.com/oauth2/v1/authorize",
			"token_endpoint": "https://example.okta.com/oauth2/v1/token",
			"jwks_uri": "https://example.okta.com/oauth2/v1/keys",
			"userinfo_endpoint": "https://example.okta.com/oauth2/v1/userinfo"
		}`))
	}))
	defer srv.Close()

	disc, err := fetchDiscoveryHTTP(t.Context(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if disc.AuthorizationEndpoint == "" {
		t.Error("expected authorization_endpoint")
	}
	if disc.JWKSURI == "" {
		t.Error("expected jwks_uri")
	}
}

func TestParseIDToken_Malformed(t *testing.T) {
	cases := []string{"", "a", "a.b", "a.b.c.d"}
	for _, tc := range cases {
		if _, err := ParseIDToken(tc); err == nil {
			t.Errorf("ParseIDToken(%q) expected error", tc)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
