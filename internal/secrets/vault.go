package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// VaultProvider reads secrets from a HashiCorp Vault KV v2 mount.
//
// We hand-roll the HTTP client (rather than pulling github.com/hashicorp/
// vault/api) to keep go.mod small. The KV v2 surface we need is just GET on
// /v1/{mount}/data/{path}; that's a 50-line client.
//
// Auth: token auth only (Vault token in VAULT_TOKEN env var). For AppRole or
// Kubernetes auth, run an external sidecar that mints a token and writes it
// into VAULT_TOKEN before binary start (vault-agent does this out-of-the-box).
//
// Concurrency: the provider caches the secret bundle on first fetch. Cache
// has no TTL — operators rotate by restarting the process. This is the
// FedRAMP-aligned pattern (per AC-7) since session secrets must not silently
// continue working after rotation.
type VaultProvider struct {
	addr      string
	token     string
	path      string // KV v2 data path, e.g. "secret/data/vsp"
	namespace string // Enterprise/HCP namespace header (optional)

	mu     sync.RWMutex
	cached map[string]string
	hc     *http.Client

	// rotatorStarted ensures StartRotator is idempotent — if main calls
	// it twice (e.g. in tests) we don't spawn duplicate watchers.
	rotatorStarted int32
}

// vaultKeyMap maps logical secret names to keys inside the KV v2 secret
// blob. The blob is fetched once and indexed locally.
var vaultKeyMap = map[string]string{
	"jwt":                "jwt_secret",
	"jwt_old":            "jwt_secret_old",
	"db_password":        "postgres_password",
	"db_url":             "database_url",
	"webhook_signing":    "webhook_signing_key",
	"redis_password":     "redis_password",
	"oidc_client_secret": "oidc_client_secret",
	"smtp_password":      "smtp_password",
	"cosign_password":    "cosign_password",
}

// NewVaultProvider validates required env vars but does not contact Vault
// — the first Get() call performs the fetch. This lets the binary boot
// even if Vault is briefly unreachable, and surfaces the failure on the
// specific secret access rather than at process start.
func NewVaultProvider() (*VaultProvider, error) {
	addr := os.Getenv("VSP_VAULT_ADDR")
	if addr == "" {
		addr = os.Getenv("VAULT_ADDR")
	}
	if addr == "" {
		return nil, errors.New("secrets/vault: VSP_VAULT_ADDR (or VAULT_ADDR) required")
	}
	token := os.Getenv("VSP_VAULT_TOKEN")
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		return nil, errors.New("secrets/vault: VSP_VAULT_TOKEN (or VAULT_TOKEN) required")
	}
	path := os.Getenv("VSP_VAULT_PATH")
	if path == "" {
		path = "secret/data/vsp"
	}
	return &VaultProvider{
		addr:      strings.TrimRight(addr, "/"),
		token:     token,
		path:      strings.TrimLeft(path, "/"),
		namespace: os.Getenv("VSP_VAULT_NAMESPACE"),
		hc:        &http.Client{Timeout: 8 * time.Second},
	}, nil
}

func (v *VaultProvider) Source() string { return "vault" }

func (v *VaultProvider) Get(name string) (string, error) {
	if err := v.ensureCache(); err != nil {
		return "", err
	}
	key, ok := vaultKeyMap[name]
	if !ok {
		key = name
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	val, ok := v.cached[key]
	if !ok || val == "" {
		return "", ErrNotFound
	}
	return val, nil
}

// ensureCache fetches the KV v2 secret on first access. Subsequent calls
// are RW-mutex-protected no-ops.
func (v *VaultProvider) ensureCache() error {
	v.mu.RLock()
	if v.cached != nil {
		v.mu.RUnlock()
		return nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cached != nil {
		return nil
	}

	url := fmt.Sprintf("%s/v1/%s", v.addr, v.path)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("secrets/vault: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", v.token)
	if v.namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.namespace)
	}
	resp, err := v.hc.Do(req)
	if err != nil {
		return fmt.Errorf("secrets/vault: request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("secrets/vault: HTTP %d from %s: %s",
			resp.StatusCode, url, truncate(string(body), 200))
	}
	var parsed struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("secrets/vault: parse response: %w", err)
	}
	cache := make(map[string]string, len(parsed.Data.Data))
	for k, raw := range parsed.Data.Data {
		// KV v2 values come in as any; we only support strings.
		if s, ok := raw.(string); ok {
			cache[k] = s
		}
	}
	v.cached = cache
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
