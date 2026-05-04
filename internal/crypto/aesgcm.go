// Package crypto provides AES-256-GCM encryption helpers.
// Used by SOAR secrets vault, autopr token storage, and any other
// at-rest encryption needs in VSP.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// ErrInvalidKey returned when key derivation fails.
var ErrInvalidKey = errors.New("crypto: invalid key length")

// ErrCiphertextTooShort returned when ciphertext is shorter than nonce size.
var ErrCiphertextTooShort = errors.New("crypto: ciphertext too short")

// ErrTamper returned when GCM auth tag check fails.
var ErrTamper = errors.New("crypto: ciphertext tampered or wrong key")

// AESGCM wraps AES-256-GCM with a derived 32-byte key.
type AESGCM struct {
	key []byte // 32 bytes
}

// NewFromPassphrase derives a 32-byte key from any-length passphrase
// using SHA-256. Suitable for env-var-based keys (e.g. VSP_REPO_KEY).
//
// Note: this is a key derivation function (KDF), not a password hash.
// For password storage use bcrypt/argon2 instead.
func NewFromPassphrase(passphrase string) (*AESGCM, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("%w: empty passphrase", ErrInvalidKey)
	}
	h := sha256.Sum256([]byte(passphrase))
	return &AESGCM{key: h[:]}, nil
}

// NewFromKey wraps an existing 32-byte key.
func NewFromKey(key []byte) (*AESGCM, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32", ErrInvalidKey, len(key))
	}
	cp := make([]byte, 32)
	copy(cp, key)
	return &AESGCM{key: cp}, nil
}

// Encrypt encrypts plaintext, returning (nonce, ciphertext) separately
// so they can be stored in distinct DB columns. Caller stores both.
//
// Nonce is randomly generated via crypto/rand. NEVER reuse nonces with
// the same key — that breaks GCM security entirely.
func (a *AESGCM) Encrypt(plaintext []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("nonce gen: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// Decrypt is the inverse of Encrypt. Returns ErrTamper if the auth tag
// doesn't match (wrong key OR ciphertext was modified).
func (a *AESGCM) Decrypt(nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: nonce size %d != %d", ErrCiphertextTooShort, len(nonce), gcm.NonceSize())
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrTamper
	}
	return plaintext, nil
}

// EncryptString is a convenience wrapper for string plaintext.
func (a *AESGCM) EncryptString(s string) (nonce, ciphertext []byte, err error) {
	return a.Encrypt([]byte(s))
}

// DecryptString returns plaintext as string. Caller MUST wipe the result
// from memory after use if it's a secret (use Wipe).
func (a *AESGCM) DecryptString(nonce, ciphertext []byte) (string, error) {
	pt, err := a.Decrypt(nonce, ciphertext)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// Wipe overwrites the byte slice with zeros. Best-effort: Go GC may have
// already moved memory. For real secrets, use locked memory.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
