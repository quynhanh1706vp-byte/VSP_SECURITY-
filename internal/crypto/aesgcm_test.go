package crypto

import (
	"bytes"
	"testing"
)

func TestNewFromPassphrase_RoundTrip(t *testing.T) {
	c, err := NewFromPassphrase("test-secret-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("hello world, this is a secret")
	nonce, ct, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Decrypt(nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestNewFromKey_RejectsWrongLength(t *testing.T) {
	_, err := NewFromKey(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestEncrypt_NonceIsRandom(t *testing.T) {
	c, _ := NewFromPassphrase("k")
	n1, _, _ := c.Encrypt([]byte("x"))
	n2, _, _ := c.Encrypt([]byte("x"))
	if bytes.Equal(n1, n2) {
		t.Fatal("nonces are identical — RNG broken")
	}
}

func TestDecrypt_TamperDetected(t *testing.T) {
	c, _ := NewFromPassphrase("k")
	nonce, ct, _ := c.Encrypt([]byte("hello"))
	// Flip 1 bit in ciphertext
	ct[0] ^= 0x01
	_, err := c.Decrypt(nonce, ct)
	if err != ErrTamper {
		t.Fatalf("expected ErrTamper, got %v", err)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	c1, _ := NewFromPassphrase("key1")
	c2, _ := NewFromPassphrase("key2")
	nonce, ct, _ := c1.Encrypt([]byte("hello"))
	_, err := c2.Decrypt(nonce, ct)
	if err != ErrTamper {
		t.Fatalf("expected ErrTamper for wrong key, got %v", err)
	}
}

func TestWipe(t *testing.T) {
	b := []byte("secret")
	Wipe(b)
	for i, x := range b {
		if x != 0 {
			t.Fatalf("byte %d not zeroed: 0x%x", i, x)
		}
	}
}

func TestEncryptString(t *testing.T) {
	c, _ := NewFromPassphrase("k")
	nonce, ct, err := c.EncryptString("api-token-xyz")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.DecryptString(nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	if got != "api-token-xyz" {
		t.Fatalf("got %q", got)
	}
}
