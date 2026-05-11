// Package crypto: error-path and edge-case pinning tests.
// L60 catches "internal/crypto under-tested" via _test.go count;
// L11 mutation runner mutates this package and these tests pin
// the invariants that would otherwise let mutations survive.

package crypto

import (
	"errors"
	"strings"
	"testing"
)

// TestErrInvalidKey_Sentinel pins the exported sentinel. If a refactor
// renames it, dependents (e.g. SOAR vault init) will fail to compile.
func TestErrInvalidKey_Sentinel(t *testing.T) {
	if ErrInvalidKey == nil {
		t.Fatal("ErrInvalidKey must be a non-nil sentinel")
	}
	if !strings.Contains(ErrInvalidKey.Error(), "invalid key") {
		t.Fatalf("ErrInvalidKey message drift: %q", ErrInvalidKey.Error())
	}
}

// TestErrCiphertextTooShort_Sentinel pins the second sentinel.
func TestErrCiphertextTooShort_Sentinel(t *testing.T) {
	if ErrCiphertextTooShort == nil {
		t.Fatal("ErrCiphertextTooShort must be non-nil")
	}
	if !strings.Contains(ErrCiphertextTooShort.Error(), "too short") {
		t.Fatalf("ErrCiphertextTooShort message drift: %q",
			ErrCiphertextTooShort.Error())
	}
}

// TestErrTamper_Sentinel pins the third sentinel. The wrapped error
// in DecryptString MUST be ErrTamper, otherwise callers that switch
// on err type (e.g. for retry vs abort decisions) will hit the
// default branch.
func TestErrTamper_Sentinel(t *testing.T) {
	if ErrTamper == nil {
		t.Fatal("ErrTamper must be non-nil")
	}
	if !strings.Contains(strings.ToLower(ErrTamper.Error()), "tamper") {
		t.Fatalf("ErrTamper message drift: %q", ErrTamper.Error())
	}
}

// TestDecrypt_ShortCiphertext_L60 exercises the ciphertext-length guard.
// A mutation removing this check would surface here.
func TestDecrypt_ShortCiphertext_L60(t *testing.T) {
	g, err := NewFromPassphrase("test-passphrase-for-l60-pinning")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Pass an empty nonce + too-short ciphertext.
	_, err = g.DecryptString([]byte{}, []byte("short"))
	if err == nil {
		t.Fatal("decrypting with an empty nonce should fail")
	}
}

// TestEncryptDecrypt_RoundTrip_L60 pins the happy-path invariant.
// What goes in comes out byte-identical. A mutation that swaps the
// plaintext / ciphertext arguments would fail here.
func TestEncryptDecrypt_RoundTrip_L60(t *testing.T) {
	g, err := NewFromPassphrase("round-trip-passphrase-l60")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	original := "the-quick-brown-fox-jumps-over-the-lazy-dog"

	nonce, ct, err := g.EncryptString(original)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(nonce) == 0 {
		t.Fatal("nonce must be non-empty (GCM standard nonce is 12 bytes)")
	}
	if len(ct) <= len(original) {
		t.Fatalf("ciphertext (%d) must be longer than plaintext (%d) — GCM adds 16-byte auth tag",
			len(ct), len(original))
	}

	pt, err := g.DecryptString(nonce, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pt != original {
		t.Fatalf("round-trip mismatch: got %q want %q", pt, original)
	}
}

// TestDecrypt_WrongKey_L60 pins the auth-tag failure mode. Encrypting
// with key A and decrypting with key B MUST fail with ErrTamper
// (wrapped) — a mutation that ignores the GCM auth tag would let B
// decrypt to garbage. (Renamed _L60 because aesgcm_test.go already
// has TestDecrypt_WrongKey.)
func TestDecrypt_WrongKey_L60(t *testing.T) {
	gA, _ := NewFromPassphrase("key-A-pinning-l60")
	gB, _ := NewFromPassphrase("key-B-different-l60")

	nonce, ct, err := gA.EncryptString("secret-data")
	if err != nil {
		t.Fatalf("encrypt with A: %v", err)
	}
	_, err = gB.DecryptString(nonce, ct)
	if err == nil {
		t.Fatal("decrypting A's ciphertext with B's key should fail GCM auth")
	}
	if !errors.Is(err, ErrTamper) {
		t.Fatalf("expected ErrTamper, got: %v", err)
	}
}

// TestDecrypt_TamperedCiphertext_L60 pins detection of an in-place
// edit of the ciphertext bytes. GCM's auth tag covers the ciphertext,
// so flipping any bit triggers the tamper check.
func TestDecrypt_TamperedCiphertext_L60(t *testing.T) {
	g, _ := NewFromPassphrase("tamper-detection-passphrase")
	nonce, ct, err := g.EncryptString("untampered")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext is empty")
	}
	ct[0] ^= 0x01 // flip one bit

	_, err = g.DecryptString(nonce, ct)
	if err == nil {
		t.Fatal("tampered ciphertext should fail GCM auth")
	}
	if !errors.Is(err, ErrTamper) {
		t.Fatalf("expected ErrTamper on bit-flip, got: %v", err)
	}
}
