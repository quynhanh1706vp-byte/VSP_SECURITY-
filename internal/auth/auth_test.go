package auth

import (
	"context"
	"testing"
	"time"
)

func TestIssueAndParseJWT(t *testing.T) {
	secret := "test-secret-32-bytes-long-enough!"
	claims := Claims{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Role:     "admin",
		Email:    "admin@test.com",
	}

	token, err := IssueJWT(secret, claims, time.Hour)
	if err != nil {
		t.Fatalf("IssueJWT failed: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	parsed, err := parseJWT(token, secret)
	if err != nil {
		t.Fatalf("parseJWT failed: %v", err)
	}
	if parsed.UserID != claims.UserID {
		t.Errorf("UserID: got %q want %q", parsed.UserID, claims.UserID)
	}
	if parsed.Role != claims.Role {
		t.Errorf("Role: got %q want %q", parsed.Role, claims.Role)
	}
}

func TestJWTExpiry(t *testing.T) {
	secret := "test-secret-32-bytes-long-enough!"
	claims := Claims{UserID: "u1", TenantID: "t1", Role: "analyst"}

	// Issue token yang sudah expired
	token, err := IssueJWT(secret, claims, -time.Second)
	if err != nil {
		t.Fatalf("IssueJWT failed: %v", err)
	}

	_, err = parseJWT(token, secret)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestJWTWrongSecret(t *testing.T) {
	token, _ := IssueJWT("secret-a", Claims{UserID: "u1", TenantID: "t1"}, time.Hour)
	_, err := parseJWT(token, "secret-b")
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret failed: %v", err)
	}

	// Generate code cho thời điểm hiện tại
	code, err := TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("TOTPCode failed: %v", err)
	}

	if !VerifyTOTP(secret, code) {
		t.Error("VerifyTOTP should return true for current code")
	}

	if VerifyTOTP(secret, "000000") {
		t.Error("VerifyTOTP should return false for invalid code (usually)")
	}
}

func TestTOTPProvisioningURI(t *testing.T) {
	uri := TOTPProvisioningURI("MYSECRET", "user@test.com", "VSP")
	if uri == "" {
		t.Fatal("expected non-empty URI")
	}
	if !contains(uri, "otpauth://totp/") {
		t.Errorf("URI should start with otpauth://totp/, got: %s", uri)
	}
	if !contains(uri, "MYSECRET") {
		t.Error("URI should contain secret")
	}
}

func TestFromContext(t *testing.T) {
	// Empty context
	_, ok := FromContext(context.Background())
	if ok {
		t.Error("FromContext should return false for empty context")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub { return true }
		}
		return false
	}())
}
