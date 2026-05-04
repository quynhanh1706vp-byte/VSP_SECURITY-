package soar

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// In-memory mock secrets store
type memSecretsStore struct {
	mu   sync.Mutex
	data map[string]struct {
		Enc, Nonce []byte
		Desc       string
		CreatedBy  string
		CreatedAt  time.Time
		Used       int64
	}
	auditLog []string
	getErr   error
}

func newMemSecrets() *memSecretsStore {
	return &memSecretsStore{
		data: make(map[string]struct {
			Enc, Nonce []byte
			Desc       string
			CreatedBy  string
			CreatedAt  time.Time
			Used       int64
		}),
	}
}

func (m *memSecretsStore) key(tid, name string) string { return tid + "|" + name }

func (m *memSecretsStore) GetSecret(ctx context.Context, tid, name string) ([]byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, nil, m.getErr
	}
	d, ok := m.data[m.key(tid, name)]
	if !ok {
		return nil, nil, errors.New("not found")
	}
	return d.Enc, d.Nonce, nil
}

func (m *memSecretsStore) UpsertSecret(ctx context.Context, tid, name, desc string, enc, nonce []byte, by string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[m.key(tid, name)] = struct {
		Enc, Nonce []byte
		Desc       string
		CreatedBy  string
		CreatedAt  time.Time
		Used       int64
	}{Enc: enc, Nonce: nonce, Desc: desc, CreatedBy: by, CreatedAt: time.Now()}
	return nil
}

func (m *memSecretsStore) DeleteSecret(ctx context.Context, tid, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, m.key(tid, name))
	return nil
}

func (m *memSecretsStore) ListSecrets(ctx context.Context, tid string) ([]SecretMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SecretMetadata
	for k, v := range m.data {
		// k = tid|name
		nameStart := len(tid) + 1
		if k[:len(tid)] != tid {
			continue
		}
		out = append(out, SecretMetadata{
			Name: k[nameStart:], Description: v.Desc,
			CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt,
			UseCount: v.Used,
		})
	}
	return out, nil
}

func (m *memSecretsStore) TouchSecret(ctx context.Context, tid, name, by string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.data[m.key(tid, name)]; ok {
		d.Used++
		m.data[m.key(tid, name)] = d
	}
	return nil
}

func (m *memSecretsStore) WriteSecretAudit(ctx context.Context, tid, name, runID, action, actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auditLog = append(m.auditLog, action+"|"+name+"|"+actor)
	return nil
}

// ─── Tests ───

func TestVault_PutAndResolve(t *testing.T) {
	mem := newMemSecrets()
	v, err := NewVault(mem, "test-passphrase-32-bytes-or-more!!")
	if err != nil {
		t.Fatal(err)
	}
	v.SetCacheTTL(0) // disable cache for clarity

	tid := "tenant-1"
	if err := v.Put(context.Background(), tid, "jira_token", "TOKEN-XYZ", "Jira API key", "alice"); err != nil {
		t.Fatal(err)
	}

	resolver := v.Resolver(tid, "run-1", "alice")
	got, err := resolver.Resolve(context.Background(), "jira_token")
	if err != nil {
		t.Fatal(err)
	}
	if got != "TOKEN-XYZ" {
		t.Fatalf("got %q", got)
	}
}

func TestVault_TenantIsolation(t *testing.T) {
	mem := newMemSecrets()
	v, _ := NewVault(mem, "passphrase")
	v.SetCacheTTL(0)

	v.Put(context.Background(), "t1", "key", "VALUE-T1", "", "a")
	v.Put(context.Background(), "t2", "key", "VALUE-T2", "", "a")

	r1 := v.Resolver("t1", "", "")
	r2 := v.Resolver("t2", "", "")
	v1, _ := r1.Resolve(context.Background(), "key")
	v2, _ := r2.Resolve(context.Background(), "key")
	if v1 != "VALUE-T1" || v2 != "VALUE-T2" {
		t.Fatalf("isolation broken: t1=%q t2=%q", v1, v2)
	}
}

func TestVault_NotFound(t *testing.T) {
	mem := newMemSecrets()
	v, _ := NewVault(mem, "p")
	v.SetCacheTTL(0)
	_, err := v.Resolver("t1", "", "").Resolve(context.Background(), "missing")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestVault_AuditLogged(t *testing.T) {
	mem := newMemSecrets()
	v, _ := NewVault(mem, "p")
	v.SetCacheTTL(0)
	v.Put(context.Background(), "t1", "key", "secret", "", "alice")
	resolver := v.Resolver("t1", "run-1", "bob")
	resolver.Resolve(context.Background(), "key")

	mem.mu.Lock()
	defer mem.mu.Unlock()
	if len(mem.auditLog) < 2 { // create + access
		t.Fatalf("audit entries: %v", mem.auditLog)
	}
	hasAccess := false
	for _, e := range mem.auditLog {
		if e == "access|key|bob" {
			hasAccess = true
		}
	}
	if !hasAccess {
		t.Fatalf("access not audited: %v", mem.auditLog)
	}
}

func TestVault_Cache(t *testing.T) {
	mem := newMemSecrets()
	v, _ := NewVault(mem, "p")
	v.SetCacheTTL(time.Second)
	v.Put(context.Background(), "t1", "key", "v1", "", "a")

	r := v.Resolver("t1", "", "")
	g1, _ := r.Resolve(context.Background(), "key")

	// Tamper backing store; cache should still serve old value
	mem.getErr = errors.New("db down")
	g2, err := r.Resolve(context.Background(), "key")
	mem.getErr = nil

	if g1 != "v1" || g2 != "v1" || err != nil {
		t.Fatalf("cache miss: g1=%q g2=%q err=%v", g1, g2, err)
	}
}

func TestVault_PutInvalidatesCache(t *testing.T) {
	mem := newMemSecrets()
	v, _ := NewVault(mem, "p")
	v.SetCacheTTL(time.Hour) // long TTL
	v.Put(context.Background(), "t1", "key", "v1", "", "a")

	r := v.Resolver("t1", "", "")
	g1, _ := r.Resolve(context.Background(), "key")

	v.Put(context.Background(), "t1", "key", "v2", "", "a") // overwrite
	g2, _ := r.Resolve(context.Background(), "key")

	if g1 != "v1" || g2 != "v2" {
		t.Fatalf("invalidate failed: g1=%q g2=%q", g1, g2)
	}
}

func TestMaskInOutput(t *testing.T) {
	s := "Bearer TOKEN-ABC123 sent to api"
	out := MaskInOutput(s, "TOKEN-ABC123")
	if out != "Bearer [REDACTED] sent to api" {
		t.Fatalf("got %q", out)
	}
}

func TestNewVault_EmptyPassphraseRejected(t *testing.T) {
	mem := newMemSecrets()
	_, err := NewVault(mem, "")
	if !errors.Is(err, ErrSecretNoVault) {
		t.Fatalf("expected ErrSecretNoVault, got %v", err)
	}
}
