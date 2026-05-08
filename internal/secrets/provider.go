// Package secrets provides a thin abstraction over secret material so the
// gateway, scheduler, and other binaries can be configured to load secrets
// from either environment variables (default, dev) or HashiCorp Vault (prod
// / DoD / FedRAMP-aligned deployments).
//
// Selection: env var VSP_SECRETS_PROVIDER = "env" (default) | "vault".
//
// Vault provider: KV v2, token auth. Path is configurable via VSP_VAULT_PATH
// (default: "secret/data/vsp"). For other auth methods (AppRole, Kubernetes,
// AWS IAM) callers should fetch the token externally and inject it via
// VAULT_TOKEN before binary start.
//
// Secrets are *cached in-memory* on first read for the lifetime of the
// process. We deliberately do not auto-rotate — rotation is operator-driven
// via SIGHUP / restart. This keeps the trust boundary simple: a leaked Vault
// token can read once, but doesn't grant continuous access if the operator
// rotates the token before SIGHUP.
package secrets

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Provider is the secret-material lookup contract.
type Provider interface {
	// Get returns the secret value for the given logical name (e.g. "jwt",
	// "db_password", "webhook_signing_key"). Logical names are mapped to
	// provider-specific addresses inside the implementation.
	Get(name string) (string, error)
	// Source returns a short identifier for this provider, used in /healthz.
	Source() string
}

var (
	defaultProvider Provider
	once            sync.Once
	initErr         error
)

// Default returns the process-wide default provider, lazily initialised
// from env config the first time it's called.
func Default() (Provider, error) {
	once.Do(func() {
		defaultProvider, initErr = New(os.Getenv("VSP_SECRETS_PROVIDER"))
	})
	return defaultProvider, initErr
}

// New constructs a Provider by source name. "" or "env" → env vars;
// "vault" → Vault KV v2 (token auth).
func New(source string) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "env":
		return &EnvProvider{}, nil
	case "vault":
		return NewVaultProvider()
	default:
		return nil, fmt.Errorf("secrets: unknown provider %q", source)
	}
}

// MustGet is a small convenience for binaries that should fail-fast when a
// secret is missing. Logs the source so it's clear in startup output.
func MustGet(p Provider, name string) string {
	v, err := p.Get(name)
	if err != nil {
		panic(fmt.Sprintf("secrets: required secret %q from %s: %v", name, p.Source(), err))
	}
	return v
}

// ErrNotFound is returned when a secret is not present in the source.
// Callers can fall back to defaults or fail-fast on this.
var ErrNotFound = errors.New("secrets: not found")
