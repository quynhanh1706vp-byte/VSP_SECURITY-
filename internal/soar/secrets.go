package soar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vsp/platform/internal/crypto"
)

// Secrets vault errors.
var (
	ErrSecretNotFound = errors.New("secret: not found")
	ErrSecretNoVault  = errors.New("secret: vault not configured")
	ErrSecretExpired  = errors.New("secret: expired")
)

// SecretsStore — minimal interface that the engine needs from store.DB.
// Implemented by *store.DB in production, mocked in tests.
type SecretsStore interface {
	GetSecret(ctx context.Context, tenantID, name string) (encValue, nonce []byte, err error)
	UpsertSecret(ctx context.Context, tenantID, name, description string, encValue, nonce []byte, createdBy string) error
	DeleteSecret(ctx context.Context, tenantID, name string) error
	ListSecrets(ctx context.Context, tenantID string) ([]SecretMetadata, error)
	TouchSecret(ctx context.Context, tenantID, name, usedBy string) error
	WriteSecretAudit(ctx context.Context, tenantID, name, runID, action, actor string) error
}

// SecretMetadata — public-safe info about a secret (no value).
type SecretMetadata struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	LastUsedBy  string     `json:"last_used_by,omitempty"`
	UseCount    int64      `json:"use_count"`
}

// Vault — encrypted per-tenant secrets store with audit log.
//
// Threat model:
//
//   - DB compromise (read-only): attacker sees ciphertext + nonce, cannot decrypt
//     without VSP_REPO_KEY env.
//   - Code execution on app server: attacker has access to plaintext during
//     decryption → mitigated by Wipe() after step + short-lived cache.
//   - Curious operator: every Resolve() writes to playbook_secret_audit.
//
// Key rotation: change VSP_REPO_KEY → all existing secrets become unreadable
// (returns ErrTamper). Rotation procedure must re-encrypt before changing key.
type Vault struct {
	db       SecretsStore
	cipher   *crypto.AESGCM
	cacheMu  sync.RWMutex
	cache    map[string]cacheEntry // tenant_id|name → entry
	cacheTTL time.Duration
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

// NewVault initializes a vault. Pass passphrase from VSP_REPO_KEY env.
// Cache TTL = 30s reduces DB hits for tight loops; set 0 to disable.
func NewVault(db SecretsStore, passphrase string) (*Vault, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: db nil", ErrSecretNoVault)
	}
	if passphrase == "" {
		return nil, fmt.Errorf("%w: passphrase empty (set VSP_REPO_KEY)", ErrSecretNoVault)
	}
	c, err := crypto.NewFromPassphrase(passphrase)
	if err != nil {
		return nil, err
	}
	return &Vault{
		db:       db,
		cipher:   c,
		cache:    make(map[string]cacheEntry),
		cacheTTL: 30 * time.Second,
	}, nil
}

// SetCacheTTL — for tests or reconfiguration. 0 disables cache.
func (v *Vault) SetCacheTTL(d time.Duration) {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	v.cacheTTL = d
	v.cache = make(map[string]cacheEntry)
}

// Put stores or updates a secret. Description optional, name must be non-empty.
func (v *Vault) Put(ctx context.Context, tenantID, name, value, description, actor string) error {
	if name == "" {
		return errors.New("secret: name required")
	}
	if value == "" {
		return errors.New("secret: value required")
	}
	nonce, ct, err := v.cipher.EncryptString(value)
	if err != nil {
		return err
	}
	if err := v.db.UpsertSecret(ctx, tenantID, name, description, ct, nonce, actor); err != nil {
		return err
	}
	_ = v.db.WriteSecretAudit(ctx, tenantID, name, "", "create", actor)
	v.invalidate(tenantID, name)
	return nil
}

// Delete removes a secret.
func (v *Vault) Delete(ctx context.Context, tenantID, name, actor string) error {
	if err := v.db.DeleteSecret(ctx, tenantID, name); err != nil {
		return err
	}
	_ = v.db.WriteSecretAudit(ctx, tenantID, name, "", "delete", actor)
	v.invalidate(tenantID, name)
	return nil
}

// List returns metadata only (no values).
func (v *Vault) List(ctx context.Context, tenantID string) ([]SecretMetadata, error) {
	return v.db.ListSecrets(ctx, tenantID)
}

// Resolver returns a SecretsResolver bound to a specific run for audit purposes.
// Use this inside Engine.Execute to give the sandbox a tenant+run-scoped resolver.
func (v *Vault) Resolver(tenantID, runID, actor string) SecretsResolver {
	return &boundResolver{vault: v, tenantID: tenantID, runID: runID, actor: actor}
}

// resolveInternal — does the actual decrypt + audit + cache.
func (v *Vault) resolveInternal(ctx context.Context, tenantID, name, runID, actor string) (string, error) {
	if name == "" {
		return "", errors.New("secret: name required")
	}

	// Audit BEFORE decrypt (so we log even if decrypt fails)
	_ = v.db.WriteSecretAudit(ctx, tenantID, name, runID, "access", actor)

	// Cache hit?
	cacheKey := tenantID + "|" + name
	if v.cacheTTL > 0 {
		v.cacheMu.RLock()
		ent, ok := v.cache[cacheKey]
		v.cacheMu.RUnlock()
		if ok && time.Now().Before(ent.expiresAt) {
			// Still touch usage stats (debounced upstream)
			go func() {
				bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = v.db.TouchSecret(bgCtx, tenantID, name, actor)
			}()
			return ent.value, nil
		}
	}

	encValue, nonce, err := v.db.GetSecret(ctx, tenantID, name)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrSecretNotFound, name)
	}
	plaintext, err := v.cipher.DecryptString(nonce, encValue)
	if err != nil {
		return "", fmt.Errorf("decrypt %q: %w", name, err)
	}

	// Update last_used
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = v.db.TouchSecret(bgCtx, tenantID, name, actor)
	}()

	// Cache
	if v.cacheTTL > 0 {
		v.cacheMu.Lock()
		v.cache[cacheKey] = cacheEntry{
			value:     plaintext,
			expiresAt: time.Now().Add(v.cacheTTL),
		}
		v.cacheMu.Unlock()
	}

	return plaintext, nil
}

func (v *Vault) invalidate(tenantID, name string) {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	delete(v.cache, tenantID+"|"+name)
}

// boundResolver — implements SecretsResolver, scoped to a run.
type boundResolver struct {
	vault    *Vault
	tenantID string
	runID    string
	actor    string
}

func (b *boundResolver) Resolve(ctx context.Context, name string) (string, error) {
	return b.vault.resolveInternal(ctx, b.tenantID, name, b.runID, b.actor)
}

// MaskInOutput — replaces secret values in a string with [REDACTED].
// Useful for sanitizing step outputs that may have accidentally
// embedded a secret. Caller passes known secret values.
func MaskInOutput(s string, secrets ...string) string {
	out := s
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		out = strReplaceAll(out, sec, "[REDACTED]")
	}
	return out
}

// strReplaceAll — local impl
func strReplaceAll(s, old, new string) string {
	if old == "" || s == "" {
		return s
	}
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	if len(sub) > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
