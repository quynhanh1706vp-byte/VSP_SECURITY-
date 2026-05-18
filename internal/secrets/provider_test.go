package secrets

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestEnvProvider_AliasAndFallback(t *testing.T) {
	t.Setenv("JWT_SECRET", "abc123")
	t.Setenv("CUSTOM_THING", "xyz")
	p := &EnvProvider{}

	// Aliased name resolves via envAliases.
	got, err := p.Get("jwt")
	if err != nil || got != "abc123" {
		t.Fatalf("alias lookup: got=%q err=%v", got, err)
	}

	// Unknown name falls back to upper-cased key.
	got, err = p.Get("custom_thing")
	if err != nil || got != "xyz" {
		t.Fatalf("fallback lookup: got=%q err=%v", got, err)
	}

	// Missing → ErrNotFound.
	if _, err := p.Get("definitely_missing_secret"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestVaultProvider_KVv2Read(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			http.Error(w, "no token", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/v1/secret/data/vsp" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":{"jwt_secret":"vault-jwt","postgres_password":"vault-db"}}}`))
	}))
	defer srv.Close()

	t.Setenv("VSP_VAULT_ADDR", srv.URL)
	t.Setenv("VSP_VAULT_TOKEN", "test-token")
	os.Unsetenv("VSP_VAULT_PATH")
	os.Unsetenv("VSP_VAULT_NAMESPACE")

	p, err := NewVaultProvider()
	if err != nil {
		t.Fatalf("NewVaultProvider: %v", err)
	}
	got, err := p.Get("jwt")
	if err != nil || got != "vault-jwt" {
		t.Fatalf("jwt: got=%q err=%v", got, err)
	}
	got, err = p.Get("db_password")
	if err != nil || got != "vault-db" {
		t.Fatalf("db_password: got=%q err=%v", got, err)
	}
	if _, err := p.Get("nope"); err != ErrNotFound {
		t.Fatalf("missing key: expected ErrNotFound, got %v", err)
	}
}

func TestNew_UnknownProvider(t *testing.T) {
	if _, err := New("hsm"); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}
