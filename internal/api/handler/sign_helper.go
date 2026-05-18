package handler

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// signDigestECDSA ký artifact digest bằng ECDSA P-256.
// FIX #5: thay thế placeholder "MEUCIQD" + digest[7:39]...
// Input:  privKeyPEM — PEM string (EC PRIVATE KEY hoặc PKCS8)
//         digestWithPrefix — "sha256:abcdef1234..."
// Output: base64-encoded DER signature (tương thích cosign bundle format)
// TODO khi có KMS: xóa hàm này, dùng KMS.Sign(keyRef, digestBytes).
func signDigestECDSA(privKeyPEM, digestWithPrefix string) (string, error) {
	if strings.TrimSpace(privKeyPEM) == "" {
		return "", fmt.Errorf("no private key available; configure KMS or provide key PEM")
	}

	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block from private key")
	}

	var privKey *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse EC private key: %w", err)
		}
		privKey = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse PKCS8 private key: %w", err)
		}
		var ok bool
		privKey, ok = k.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("key is not ECDSA (got %T)", k)
		}
	default:
		return "", fmt.Errorf("unsupported PEM block type: %q", block.Type)
	}

	hexDigest := strings.TrimPrefix(digestWithPrefix, "sha256:")
	if len(hexDigest) != 64 {
		return "", fmt.Errorf("invalid sha256 hex length: %d (expected 64)", len(hexDigest))
	}

	var digestBytes [32]byte
	for i := 0; i < 32; i++ {
		var b byte
		fmt.Sscanf(hexDigest[i*2:i*2+2], "%02x", &b)
		digestBytes[i] = b
	}

	sig, err := privKey.Sign(rand.Reader, digestBytes[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("ecdsa sign: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}
