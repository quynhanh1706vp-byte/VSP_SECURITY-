package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

func (a *Auth) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		MFACode         string `json:"mfa_code,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		jsonError(w, "current_password and new_password required", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 12 {
		jsonError(w, "new_password must be at least 12 characters", http.StatusBadRequest)
		return
	}
	if req.CurrentPassword == req.NewPassword {
		jsonError(w, "new_password must differ from current password", http.StatusBadRequest)
		return
	}
	user, err := a.DB.GetUserByID(r.Context(), claims.TenantID, claims.UserID)
	if err != nil || user == nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PwHash), []byte(req.CurrentPassword)); err != nil {
		// Failed login counter increment MUST survive the response.
		// Pre-fix, the r.Context() goroutine raced response cancel and
		// often dropped the increment under load → brute force not
		// rate-limited by failed_logins ratchet.
		uid := user.ID
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = a.DB.RecordFailedLogin(ctx, uid)
		}()
		jsonError(w, "current password is incorrect", http.StatusUnauthorized)
		return
	}
	if user.MFAEnabled && user.MFAVerified {
		if req.MFACode == "" {
			jsonError(w, "mfa_code required to change password", http.StatusBadRequest)
			return
		}
		if !auth.VerifyTOTP(user.MFASecret, req.MFACode) {
			jsonError(w, "invalid MFA code", http.StatusUnauthorized)
			return
		}
	}
	reused, err := a.DB.IsPasswordReused(r.Context(), claims.UserID, req.NewPassword)
	if err == nil && reused {
		jsonError(w, "new_password was recently used — choose a different password", http.StatusBadRequest)
		return
	}
	// HIBP breach check (NIST SP 800-63B-3 §5.1.1.2). Permissive by default —
	// network failures don't block the change. Set VSP_HIBP_REQUIRED=1 to
	// flip to strict mode.
	if err := auth.CheckPasswordBreached(r.Context(), req.NewPassword); err != nil {
		switch err {
		case auth.ErrPasswordBreached:
			jsonError(w, "new_password appears in known breach corpus — choose a different password", http.StatusBadRequest)
		case auth.ErrHIBPUnavailable:
			jsonError(w, "password breach service unavailable — try again", http.StatusServiceUnavailable)
		default:
			// Unexpected — fail closed only when strict mode is forced upstream.
		}
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := a.DB.UpdatePassword(r.Context(), claims.UserID, string(newHash)); err != nil {
		jsonError(w, "failed to update password", http.StatusInternalServerError)
		return
	}
	// SECURITY: refresh-token revoke MUST run to completion. The
	// pre-fix goroutine used r.Context() which the HTTP layer cancels
	// the instant the response is flushed; pgx then sees "context
	// canceled" before the DELETE executes. Result: a user changing
	// their password under load could leave old refresh tokens valid
	// — defeating the password-change-invalidates-sessions guarantee.
	uid := claims.UserID
	tid := claims.TenantID
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = a.DB.RevokeAllRefreshTokens(ctx, uid)
	}()
	go a.writeAudit(r.Clone(context.Background()), tid, &uid, "PASSWORD_CHANGED", "/auth/password/change")
	jsonOK(w, map[string]string{"message": "password changed successfully"})
}
