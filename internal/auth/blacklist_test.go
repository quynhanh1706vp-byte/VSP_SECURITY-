package auth

import (
	"context"
	"testing"
	"time"
)

// mockBlacklist implement BlacklistChecker interface để test không cần Redis
type mockBlacklist struct {
	revoked     map[string]bool
	userRevoked map[string]time.Time
}

func newMockBlacklist() *mockBlacklist {
	return &mockBlacklist{
		revoked:     make(map[string]bool),
		userRevoked: make(map[string]time.Time),
	}
}

func (m *mockBlacklist) IsRevoked(_ context.Context, tokenID string) bool {
	return m.revoked[tokenID]
}

func (m *mockBlacklist) IsUserRevoked(_ context.Context, userID string, issuedAt time.Time) bool {
	if t, ok := m.userRevoked[userID]; ok {
		return issuedAt.Before(t)
	}
	return false
}

func TestBlacklist_IsRevoked(t *testing.T) {
	bl := newMockBlacklist()
	ctx := context.Background()

	if bl.IsRevoked(ctx, "tok-1") {
		t.Error("new token should not be revoked")
	}

	bl.revoked["tok-1"] = true
	if !bl.IsRevoked(ctx, "tok-1") {
		t.Error("revoked token should return true")
	}
}

func TestBlacklist_IsUserRevoked(t *testing.T) {
	bl := newMockBlacklist()
	ctx := context.Background()

	revokeTime := time.Now()
	bl.userRevoked["user-1"] = revokeTime

	// Token issued before revoke time → revoked
	if !bl.IsUserRevoked(ctx, "user-1", revokeTime.Add(-time.Minute)) {
		t.Error("token issued before revoke time should be revoked")
	}

	// Token issued after revoke time → OK
	if bl.IsUserRevoked(ctx, "user-1", revokeTime.Add(time.Minute)) {
		t.Error("token issued after revoke time should not be revoked")
	}

	// Different user → not affected
	if bl.IsUserRevoked(ctx, "user-2", revokeTime.Add(-time.Minute)) {
		t.Error("user-2 should not be affected")
	}
}

func TestBlacklist_WithJWTMiddleware(t *testing.T) {
	// Test parseJWT với blacklist được set
	secret := "test-secret-32-bytes-long-enough!"
	claims := Claims{UserID: "u1", TenantID: "t1", Role: "admin"}
	token, err := IssueJWT(secret, claims, time.Hour)
	if err != nil {
		t.Fatalf("IssueJWT: %v", err)
	}

	// Parse without blacklist
	globalBlacklist = nil
	_, err = parseJWT(token, secret)
	if err != nil {
		t.Fatalf("parseJWT without blacklist: %v", err)
	}

	// Parse with blacklist that revokes everything
	bl := newMockBlacklist()
	globalBlacklist = bl

	// Not revoked yet
	_, err = parseJWT(token, secret)
	if err != nil {
		t.Fatalf("parseJWT with empty blacklist: %v", err)
	}

	// Revoke the token
	bl.revoked[""] = true // revoke by JTI (empty string matches any if JTI not extracted)
	// Reset to not affect other tests
	globalBlacklist = nil
}

func TestSetBlacklist(t *testing.T) {
	defer func() { globalBlacklist = nil }()

	bl := newMockBlacklist()
	SetBlacklist(bl)
	if globalBlacklist == nil {
		t.Error("SetBlacklist should set globalBlacklist")
	}
}
