// Package auth — JWT secret rotation support.
//
// Implements dual-secret validation for zero-downtime rotation:
//   - Primary secret (passed as function param, from JWT_SECRET or
//     JWT_SECRET_NEW env var) is used for ISSUING new tokens.
//   - Old secret (from JWT_SECRET_OLD env var, optional) is accepted
//     ONLY for VALIDATING existing tokens during transition window.
//
// Operational flow:
//  1. Normal state: only JWT_SECRET set, single-key behavior.
//  2. Rotation initiated:
//     - rename existing JWT_SECRET → JWT_SECRET_OLD
//     - generate new secret → JWT_SECRET (or JWT_SECRET_NEW)
//     - reload service (gateway) — no user logout
//     - Existing tokens validated by OLD secret until expiry
//     - New tokens signed by NEW secret
//  3. After all OLD tokens expire (>= JWT_TTL, typically 24h):
//     - unset JWT_SECRET_OLD
//     - reload service — rotation complete
//
// Rationale:
//  - Rotating secrets without dual-validation → all users logged out
//    mid-session (JWT signature verification fails).
//  - FedRAMP IA-5 control requires periodic credential rotation.
//  - Dual-secret preserves user sessions across rotation.
//
// See: docs/runbooks/jwt-rotation.md (TODO)

package auth

import "os"

// resolveSecrets returns all secrets accepted for token validation.
// primary is the current signing secret (first, mandatory).
// If JWT_SECRET_OLD env var is set and different, it is appended as
// a fallback (accepted ONLY for validation, NOT for issuing).
func resolveSecrets(primary string) []string {
	if primary == "" {
		return nil
	}
	secrets := []string{primary}
	if old := os.Getenv("JWT_SECRET_OLD"); old != "" && old != primary {
		secrets = append(secrets, old)
	}
	return secrets
}

// parseJWTWithRotation attempts to parse a JWT using any of the provided
// secrets in order. Returns the first successful parse. If all fail,
// returns the error from the primary secret attempt (not the fallback),
// so error messages remain consistent with non-rotation deployments.
//
// This function is the ONLY validation entry point that callers should
// use. Direct calls to parseJWT(tokenStr, singleSecret) are kept for
// internal use and tests.
func parseJWTWithRotation(tokenStr string, secrets []string) (Claims, error) {
	if len(secrets) == 0 {
		return Claims{}, ErrNoSecretsConfigured
	}

	// Try primary first — capture its error to return if all fallbacks fail
	claims, primaryErr := parseJWT(tokenStr, secrets[0])
	if primaryErr == nil {
		return claims, nil
	}

	// Try fallbacks (JWT_SECRET_OLD during rotation window)
	for _, s := range secrets[1:] {
		if claims, err := parseJWT(tokenStr, s); err == nil {
			return claims, nil
		}
	}

	// Return error from PRIMARY attempt to not leak rotation details
	return Claims{}, primaryErr
}

// ErrNoSecretsConfigured is returned when JWT validation is attempted
// with no secrets provided. Indicates a configuration bug.
var ErrNoSecretsConfigured = errNoSecrets{}

type errNoSecrets struct{}

func (errNoSecrets) Error() string { return "jwt: no secrets configured" }
