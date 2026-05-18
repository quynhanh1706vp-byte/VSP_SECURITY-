package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IssueToken creates a JWT for SSO-authenticated users.
// Finds or creates user in DB by email.
// NOTE: This is the legacy SSO path used by /auth/sso/* routes.
// New SSO flows use sso_oidc.go → resolveOrProvisionUser instead.
func (a *Auth) IssueToken(ctx context.Context, email, name, role string) (string, error) {
	userID := "sso-" + email
	tenantID := a.DefaultTID

	// Use direct email lookup instead of O(N) ListUsers scan.
	// ListUsers has a hard cap of 100 rows — misses users beyond that.
	if u, err := a.DB.GetUserByEmail(ctx, tenantID, email); err == nil && u != nil {
		userID = u.ID
		tenantID = u.TenantID
		role = u.Role
	}

	claims := jwt.MapClaims{
		"sub":       userID,
		"email":     email,
		"tenant_id": tenantID,
		"role":      role,
		"exp":       time.Now().Add(a.JWTTTL).Unix(),
		"iat":       time.Now().Unix(),
		"sso":       true,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(a.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}
