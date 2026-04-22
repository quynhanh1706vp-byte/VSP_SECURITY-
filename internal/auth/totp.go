package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC6238 TOTP mandates HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

// GenerateTOTPSecret tạo secret 20-byte random, encode base32
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// TOTPCode tính TOTP code tại thời điểm t (RFC 6238, 30s window, 6 digits)
func TOTPCode(secret string, t time.Time) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("invalid totp secret: %w", err)
	}
	counter := uint64(math.Floor(float64(t.Unix()) / 30))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	code := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000), nil
}

// VerifyTOTP kiểm tra code với ±1 window (90s tolerance)
func VerifyTOTP(secret, code string) bool {
	now := time.Now()
	for _, delta := range []int{-1, 0, 1} {
		t := now.Add(time.Duration(delta) * 30 * time.Second)
		expected, err := TOTPCode(secret, t)
		if err != nil {
			return false
		}
		if expected == strings.TrimSpace(code) {
			return true
		}
	}
	return false
}

// TOTPProvisioningURI tạo URI để generate QR code
func TOTPProvisioningURI(secret, email, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, email, secret, issuer)
}
