package auth

import (
	"os"
	"testing"
	"time"
)

func TestResolveSecrets_PrimaryOnly(t *testing.T) {
	os.Unsetenv("JWT_SECRET_OLD")
	secrets := resolveSecrets("new-secret")
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0] != "new-secret" {
		t.Errorf("expected primary secret, got %q", secrets[0])
	}
}

func TestResolveSecrets_WithOld(t *testing.T) {
	t.Setenv("JWT_SECRET_OLD", "old-secret")
	secrets := resolveSecrets("new-secret")
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}
	if secrets[0] != "new-secret" {
		t.Errorf("primary must be first, got %q", secrets[0])
	}
	if secrets[1] != "old-secret" {
		t.Errorf("old must be second, got %q", secrets[1])
	}
}

func TestResolveSecrets_OldEqualsPrimary_NoDup(t *testing.T) {
	t.Setenv("JWT_SECRET_OLD", "same-secret")
	secrets := resolveSecrets("same-secret")
	if len(secrets) != 1 {
		t.Fatalf("duplicate secret should collapse, got %d", len(secrets))
	}
}

func TestResolveSecrets_EmptyPrimary(t *testing.T) {
	secrets := resolveSecrets("")
	if secrets != nil {
		t.Errorf("empty primary must return nil, got %v", secrets)
	}
}

func TestParseJWTWithRotation_PrimaryValid(t *testing.T) {
	secret := "primary-secret-thirty-two-chars-long"
	token, err := IssueJWT(secret, Claims{UserID: "u1", Role: "admin"}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	secrets := []string{secret}
	c, err := parseJWTWithRotation(token, secrets)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.UserID != "u1" {
		t.Errorf("expected user u1, got %q", c.UserID)
	}
}

// Simulate rotation scenario:
// 1. Token issued with OLD secret (before rotation)
// 2. Rotation: primary = NEW, fallback = OLD
// 3. Token should still validate
func TestParseJWTWithRotation_OldTokenDuringTransition(t *testing.T) {
	oldSecret := "old-secret-thirty-two-chars-long-xx"
	newSecret := "new-secret-thirty-two-chars-long-xx"

	// Token signed with OLD secret (pre-rotation)
	token, err := IssueJWT(oldSecret, Claims{UserID: "u2", Role: "user"}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Post-rotation: primary = NEW, fallback = OLD
	secrets := []string{newSecret, oldSecret}
	c, err := parseJWTWithRotation(token, secrets)
	if err != nil {
		t.Fatalf("old token must validate during transition: %v", err)
	}
	if c.UserID != "u2" {
		t.Errorf("expected u2, got %q", c.UserID)
	}
}

// Post-rotation token must validate with NEW secret even when OLD still registered
func TestParseJWTWithRotation_NewTokenWorks(t *testing.T) {
	oldSecret := "old-secret-thirty-two-chars-long-yy"
	newSecret := "new-secret-thirty-two-chars-long-yy"

	token, err := IssueJWT(newSecret, Claims{UserID: "u3", Role: "user"}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	secrets := []string{newSecret, oldSecret}
	c, err := parseJWTWithRotation(token, secrets)
	if err != nil {
		t.Fatalf("new token parse: %v", err)
	}
	if c.UserID != "u3" {
		t.Errorf("wrong user, got %q", c.UserID)
	}
}

// After rotation complete (OLD removed), old tokens must fail
func TestParseJWTWithRotation_AfterOldRemoved(t *testing.T) {
	oldSecret := "old-secret-thirty-two-chars-long-zz"
	newSecret := "new-secret-thirty-two-chars-long-zz"

	// Token signed with OLD
	token, _ := IssueJWT(oldSecret, Claims{UserID: "u4"}, time.Hour)

	// Rotation complete — only NEW secret now
	secrets := []string{newSecret}
	_, err := parseJWTWithRotation(token, secrets)
	if err == nil {
		t.Error("old token must not validate after OLD secret removed")
	}
}

func TestParseJWTWithRotation_InvalidToken(t *testing.T) {
	secrets := []string{"secret-thirty-two-chars-long-xxxx"}
	_, err := parseJWTWithRotation("not-a-jwt", secrets)
	if err == nil {
		t.Error("invalid token must return error")
	}
}

func TestParseJWTWithRotation_NoSecrets(t *testing.T) {
	_, err := parseJWTWithRotation("any-token", nil)
	if err != ErrNoSecretsConfigured {
		t.Errorf("expected ErrNoSecretsConfigured, got %v", err)
	}
}

// Integration: middleware behavior unchanged when JWT_SECRET_OLD not set
func TestRotation_BackwardCompat_NoOldSecretEnv(t *testing.T) {
	os.Unsetenv("JWT_SECRET_OLD")
	secret := "primary-secret-thirty-two-chars-xxxx"

	token, _ := IssueJWT(secret, Claims{UserID: "u5"}, time.Hour)
	secrets := resolveSecrets(secret)

	c, err := parseJWTWithRotation(token, secrets)
	if err != nil {
		t.Fatalf("backward compat failed: %v", err)
	}
	if c.UserID != "u5" {
		t.Errorf("wrong user: %q", c.UserID)
	}
}
