package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChangePasswordValidation(t *testing.T) {
	tests := []struct {
		name    string
		body    map[string]string
		wantStatus int
	}{
		{
			name:       "missing fields",
			body:       map[string]string{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "password too short",
			body:       map[string]string{"current_password": "old", "new_password": "short"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "same password",
			body:       map[string]string{"current_password": "samepass", "new_password": "samepass"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "no auth",
			body:       map[string]string{"current_password": "old1234!", "new_password": "new1234!"},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h := &Auth{} // no DB — will fail at auth check
			h.ChangePassword(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status: got %d want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}
