package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IssueToken creates a JWT for SSO-authenticated users.
// Finds or creates user in DB by email.
func (a *Auth) IssueToken(ctx context.Context, email, name, role string) (string, error) {
	// Find existing user or use default tenant
	userID := "sso-" + email
	tenantID := a.DefaultTID

	// Try to find existing user
	if users, _, err := a.DB.ListUsers(ctx, tenantID, 100, 0); err == nil {
		for _, u := range users {
			if u.Email == email {
				userID = u.ID
				tenantID = u.TenantID
				role = u.Role
				break
			}
		}
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
