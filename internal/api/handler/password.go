package handler

import (
	"net/http"

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
		go a.DB.RecordFailedLogin(r.Context(), user.ID) //nolint:errcheck
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
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := a.DB.UpdatePassword(r.Context(), claims.UserID, string(newHash)); err != nil {
		jsonError(w, "failed to update password", http.StatusInternalServerError)
		return
	}
	go a.DB.RevokeAllRefreshTokens(r.Context(), claims.UserID) //nolint:errcheck
	go a.writeAudit(r.Clone(r.Context()), claims.TenantID, &claims.UserID, "PASSWORD_CHANGED", "/auth/password/change")
	jsonOK(w, map[string]string{"message": "password changed successfully"})
}
