package handler

import (
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type SSO struct {
	Handler    *auth.OIDCHandler
	AuthH      *Auth
	mu         sync.Mutex
	states     map[string]time.Time // state → expiry
}

func NewSSO(cfg auth.OIDCConfig, authH *Auth, db *store.DB) *SSO {
	h := &SSO{
		AuthH:  authH,
		states: make(map[string]time.Time),
	}
	// Cleanup expired states every 5 minutes to prevent memory leak
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			h.mu.Lock()
			now := time.Now()
			for state, expiry := range h.states {
				if now.After(expiry) {
					delete(h.states, state)
				}
			}
			h.mu.Unlock()
		}
	}()
	if !cfg.Enabled { return h }
	// Merge preset
	if preset, ok := auth.ProviderPresets[cfg.ProviderName]; ok {
		if cfg.AuthURL == "" { cfg.AuthURL = preset.AuthURL }
		if cfg.TokenURL == "" { cfg.TokenURL = preset.TokenURL }
		if cfg.UserInfoURL == "" { cfg.UserInfoURL = preset.UserInfoURL }
		if len(cfg.Scopes) == 0 { cfg.Scopes = preset.Scopes }
	}
	h.Handler = &auth.OIDCHandler{
		Config:    cfg,
		JWTSecret: authH.JWTSecret,
		JWTTTL:   authH.JWTTTL,
	}
	return h
}

func (h *SSO) Enabled() bool { return h.Handler != nil }

// GET /auth/sso/login — redirect to provider
func (h *SSO) Login(w http.ResponseWriter, r *http.Request) {
	if !h.Enabled() {
		jsonError(w, "SSO not configured", http.StatusNotImplemented)
		return
	}
	state, err := auth.GenerateState()
	if err != nil {
		jsonError(w, "state error", http.StatusInternalServerError)
		return
	}
	h.mu.Lock()
	h.states[state] = time.Now().Add(10 * time.Minute)
	h.mu.Unlock()

	http.Redirect(w, r, h.Handler.AuthCodeURL(state), http.StatusFound)
}

// GET /auth/sso/callback — exchange code, issue JWT
func (h *SSO) Callback(w http.ResponseWriter, r *http.Request) {
	if !h.Enabled() {
		jsonError(w, "SSO not configured", http.StatusNotImplemented)
		return
	}

	state := r.URL.Query().Get("state")
	code  := r.URL.Query().Get("code")

	// Validate state
	h.mu.Lock()
	expiry, ok := h.states[state]
	delete(h.states, state)
	h.mu.Unlock()
	if !ok || time.Now().After(expiry) {
		jsonError(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	accessToken, err := h.Handler.ExchangeCode(r.Context(), code)
	if err != nil {
		log.Error().Err(err).Msg("sso: token exchange failed")
		jsonError(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	// Fetch user info
	info, err := h.Handler.FetchUserInfo(r.Context(), accessToken)
	if err != nil || info.Email == "" {
		log.Error().Err(err).Msg("sso: userinfo failed")
		jsonError(w, "userinfo failed", http.StatusBadGateway)
		return
	}

	role := h.Handler.DetermineRole(info.Email)
	log.Info().Str("email", info.Email).Str("role", role).
		Str("provider", h.Handler.Config.ProviderName).Msg("sso: login")

	// Issue JWT via existing Auth handler
	token, err := h.AuthH.IssueToken(r.Context(), info.Email, info.Name, role)
	if err != nil {
		jsonError(w, "token issue failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to dashboard with token in fragment (or return JSON)
	if r.URL.Query().Get("format") == "json" {
		jsonOK(w, map[string]any{
			"token": token,
			"email": info.Email,
			"name":  info.Name,
			"role":  role,
		})
		return
	}
	// Trả về HTML page tự inject token vào localStorage rồi redirect
	// Không để token trong URL fragment (lộ vào browser history/logs)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!DOCTYPE html><html><head><title>SSO Login</title></head><body>
<script>
try {
  localStorage.setItem('vsp_token', ` + "`" + `"` + token + `"` + "`" + `);
} catch(e) {}
window.location.replace('/');
</script>
<noscript>JavaScript required. <a href="/">Go to dashboard</a></noscript>
</body></html>`))
}

// GET /auth/sso/providers — list configured providers
func (h *SSO) Providers(w http.ResponseWriter, r *http.Request) {
	if !h.Enabled() {
		jsonOK(w, map[string]any{"providers": []string{}, "sso_enabled": false})
		return
	}
	jsonOK(w, map[string]any{
		"providers": []map[string]string{{
			"name":      h.Handler.Config.ProviderName,
			"login_url": "/auth/sso/login",
		}},
		"sso_enabled": true,
	})
}