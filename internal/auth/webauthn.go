// Package auth — WebAuthn / FIDO2 / Passkey support.
//
// VSP supports two authenticator types via the same flow:
//   - Platform authenticators (Touch ID, Face ID, Windows Hello, Android
//     biometric) — convenient daily login.
//   - Cross-platform authenticators (YubiKey, Titan, etc.) — high-
//     assurance use cases where DSOMM L4 / FedRAMP High demand a
//     hardware root of trust.
//
// We use github.com/go-webauthn/webauthn for the heavy crypto (CBOR
// decoding, COSE key parsing, attestation-statement verification). This
// package wraps the library with VSP-specific concerns:
//   - Per-tenant configurable RP ID + origin
//   - DB-backed session store (5 min TTL; replaces the library's
//     in-memory store so cluster deployments work)
//   - Credential enumeration / revocation hooks
//
// The credential store is multi-credential per user — a user can register
// a phone passkey AND a hardware key for backup. Login picks any
// non-revoked credential the authenticator presents.
package auth

import (
	"errors"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnUser is the minimal user adapter the library expects.
// Implementations live next to the user model — see internal/store.
type WebAuthnUser interface {
	WebAuthnID() []byte
	WebAuthnName() string
	WebAuthnDisplayName() string
	WebAuthnCredentials() []webauthn.Credential
}

// Config carries the runtime knobs. Origin must match exactly what the
// browser sends in the client data; mismatches break registration with
// "origin mismatch" errors that are notoriously hard to debug.
type Config struct {
	RPDisplayName string   // e.g. "VSP — Vietnam Security Platform"
	RPID          string   // e.g. "vsp.example" (no scheme/port)
	Origins       []string // e.g. ["https://vsp.example", "https://app.vsp.example"]
	// RequireUserVerification toggles the UV bit policy. PRO tenants
	// running high-assurance workloads should set this true so a stolen
	// authenticator can't auth without the local biometric/PIN.
	RequireUserVerification bool
}

// New returns a configured *webauthn.WebAuthn instance for the given
// config. Returns ErrInvalidConfig when required fields are missing.
func NewWebAuthn(cfg Config) (*webauthn.WebAuthn, error) {
	if cfg.RPID == "" || len(cfg.Origins) == 0 {
		return nil, ErrInvalidConfig
	}
	uv := protocol.VerificationDiscouraged
	if cfg.RequireUserVerification {
		uv = protocol.VerificationRequired
	}
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: nonEmpty(cfg.RPDisplayName, "VSP"),
		RPID:          cfg.RPID,
		RPOrigins:     cfg.Origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: uv,
		},
	})
	if err != nil {
		return nil, err
	}
	return w, nil
}

// ErrInvalidConfig is returned by NewWebAuthn when required fields are
// missing.
var ErrInvalidConfig = errors.New("webauthn: rp_id and origins are required")

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
