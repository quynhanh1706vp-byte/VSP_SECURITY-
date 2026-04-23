package handler

import "testing"

// MFA login flow tests — SKELETON ONLY.
//
// These tests are intentionally skipped until the required refactor and
// mock infrastructure are in place. Written now as a living TODO list so
// the next engineer knows exactly which scenarios need coverage.
//
// Why skipped (not implemented):
//
//   1. Auth struct currently holds a concrete *store.DB, not an interface.
//      See cmd/gateway/main.go wiring and handler.Auth definition. Login
//      uses a.DB.Pool().QueryRow(...) for tenant lookup, which cannot be
//      mocked without refactoring Auth to accept an interface.
//
//   2. storetest package has no UserMock. WebhookMock exists as a
//      reference pattern. A new UserMock would need to implement ~13
//      methods from store.UserStore (GetUserByEmail, GetUserByID,
//      RecordFailedLogin, ResetFailedLogins, UpdateLastLogin,
//      SetMFASecret, ConfirmMFAEnabled, DisableMFA, CreateUser,
//      ListUsers, DeleteUser, UpdatePassword, IsPasswordReused).
//
//   3. Tenant resolution (X-Tenant-Slug → tenant_id) runs raw SQL via
//      pgx pool. Either extract to store.UserStore.ResolveTenantBySlug
//      or add a dedicated TenantStore interface.
//
// Refactor scope estimate: 4-5 hours engaged work. Do in a dedicated
// PR, not mixed with feature work.
//
// Refs:
//   - PR #67 (fix/mfa-setup-race-condition) — code changes these would cover
//   - internal/store/interfaces.go — UserStore interface
//   - internal/store/storetest/mocks.go — existing WebhookMock pattern
//   - internal/api/handler/auth_handler_test.go — existing Login test
//     pattern (only negative paths, no DB)

// TestLogin_AdminMFAMissing_Production_Returns403
//
// Scenario: user.Role=admin, MFAEnabled=false, server.env=production.
// Expected: HTTP 403, error message about MFA required.
// Covers: handler/auth.go:109 admin enforcement gate.
func TestLogin_AdminMFAMissing_Production_Returns403(t *testing.T) {
	t.Skip("pending UserMock + Auth interface refactor; see file header")
}

// TestLogin_AdminMFAConfigured_NoCode_ReturnsMFARequired
//
// Scenario: user.Role=admin, MFAEnabled=true, MFAVerified=true, no mfa_code
// in request body.
// Expected: HTTP 200 with {mfa_required: true, message: "MFA code required"}.
// Covers: handler/auth.go:121 MFA challenge branch.
func TestLogin_AdminMFAConfigured_NoCode_ReturnsMFARequired(t *testing.T) {
	t.Skip("pending UserMock + Auth interface refactor; see file header")
}

// TestLogin_AdminMFAConfigured_ValidCode_IssuesJWT
//
// Scenario: user.Role=admin, MFAEnabled=true, MFAVerified=true, valid TOTP
// code in request body.
// Expected: HTTP 200 with token, MFAEnabled=true in response.
// Covers: handler/auth.go:132 MFA verify + JWT issue.
func TestLogin_AdminMFAConfigured_ValidCode_IssuesJWT(t *testing.T) {
	t.Skip("pending UserMock + Auth interface refactor; see file header")
}

// TestLogin_AnalystRole_NoMFA_AllowedRegardlessOfEnv
//
// Scenario: user.Role=analyst (non-admin), MFAEnabled=false,
// server.env=production. Valid credentials.
// Expected: HTTP 200 with token — MFA enforcement applies only to admin role.
// Covers: non-admin paths bypass the gate.
func TestLogin_AnalystRole_NoMFA_AllowedRegardlessOfEnv(t *testing.T) {
	t.Skip("pending UserMock + Auth interface refactor; see file header")
}

// TestMFA_Setup_DoesNotEnableUntilVerify
//
// Scenario: Call Setup handler → store.SetMFASecret records secret.
// Check: user.MFAEnabled is still false after Setup (only ConfirmMFAEnabled
// at Verify should flip it).
// Covers: PR #67 bug fix — SetMFASecret no longer prematurely enables MFA.
func TestMFA_Setup_DoesNotEnableUntilVerify(t *testing.T) {
	t.Skip("pending UserMock + Auth interface refactor; see file header")
}
