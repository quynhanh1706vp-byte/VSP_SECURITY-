package handler

import (
	"encoding/json"
	"net/http"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type MFA struct {
	DB *store.DB
}

// POST /api/v1/auth/mfa/setup — tạo secret và trả về QR URI
func (h *MFA) Setup(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := h.DB.SetMFASecret(r.Context(), claims.UserID, secret); err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	uri := auth.TOTPProvisioningURI(secret, claims.Email, "VSP Security Platform")
	jsonOK(w, map[string]any{
		"secret":           secret,
		"provisioning_uri": uri,
		"message":          "Scan QR code with authenticator app, then call /mfa/verify to confirm",
	})
}

// POST /api/v1/auth/mfa/verify — xác nhận setup MFA với code đầu tiên
func (h *MFA) Verify(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.TenantID, claims.UserID)
	if err != nil || user == nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	if !auth.VerifyTOTP(user.MFASecret, req.Code) {
		jsonError(w, "invalid code — check your authenticator app", http.StatusBadRequest)
		return
	}

	if err := h.DB.VerifyMFASetup(r.Context(), claims.UserID); err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{
		"message": "MFA enabled successfully",
		"status":  "enabled",
	})
}

// DELETE /api/v1/auth/mfa — disable MFA (admin only hoặc self)
func (h *MFA) Disable(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	user, err := h.DB.GetUserByID(r.Context(), claims.TenantID, claims.UserID)
	if err != nil || user == nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	// Yêu cầu xác nhận code trước khi disable
	if user.MFAEnabled && !auth.VerifyTOTP(user.MFASecret, req.Code) {
		jsonError(w, "invalid code", http.StatusBadRequest)
		return
	}

	if err := h.DB.DisableMFA(r.Context(), claims.TenantID, claims.UserID); err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{"message": "MFA disabled", "status": "disabled"})
}
