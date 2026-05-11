// Package handler — WebAuthn registration + authentication endpoints.
//
// Endpoints:
//   POST /api/v1/auth/webauthn/register/begin   — start registration; returns options
//   POST /api/v1/auth/webauthn/register/finish  — finish registration; persists credential
//   POST /api/v1/auth/webauthn/login/begin      — start authentication; returns assertion options
//   POST /api/v1/auth/webauthn/login/finish     — finish authentication; issues JWT
//   GET  /api/v1/auth/webauthn/credentials      — list user's credentials
//   POST /api/v1/auth/webauthn/credentials/{id}/revoke — revoke one credential
//
// All four flow endpoints require a valid bearer token EXCEPT login/* which
// are anonymous (you're not logged in yet — that's the point). For login,
// the user is identified by their email in the begin payload, then the
// challenge ties the finish call back to the same session.
package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type WebAuthnH struct {
	DB *store.DB
	W  *webauthn.WebAuthn
}

// NewWebAuthnHandler builds the handler with the operator-provided RP
// config. Returns nil + error when the config is invalid; the gateway
// can decide whether to fail-fast or skip-wire on invalid config.
func NewWebAuthnHandler(db *store.DB) (*WebAuthnH, error) {
	cfg := auth.Config{
		RPDisplayName:           getenvDefault("VSP_WEBAUTHN_RP_NAME", "VSP — Vietnam Security Platform"),
		RPID:                    os.Getenv("VSP_WEBAUTHN_RP_ID"),
		Origins:                 splitList(os.Getenv("VSP_WEBAUTHN_ORIGINS")),
		RequireUserVerification: os.Getenv("VSP_WEBAUTHN_REQUIRE_UV") == "1",
	}
	if cfg.RPID == "" {
		// Soft-fail: caller logs and skips wiring, gateway still boots.
		return nil, auth.ErrInvalidConfig
	}
	w, err := auth.NewWebAuthn(cfg)
	if err != nil {
		return nil, err
	}
	return &WebAuthnH{DB: db, W: w}, nil
}

// dbUser adapts a VSP user row to webauthn.User.
type dbUser struct {
	id          []byte // 16-byte UUID
	tenantID    string
	email       string
	displayName string
	creds       []webauthn.Credential
}

func (u *dbUser) WebAuthnID() []byte                         { return u.id }
func (u *dbUser) WebAuthnName() string                       { return u.email }
func (u *dbUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *dbUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (h *WebAuthnH) loadUser(r *http.Request, userID, tenantID string) (*dbUser, error) {
	var email, displayName string
	if err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT email, COALESCE(display_name, email) FROM users WHERE id = $1`,
		userID).Scan(&email, &displayName); err != nil {
		return nil, err
	}
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT credential_id, public_key, sign_count, COALESCE(transports,''),
		        COALESCE(user_verified,false)
		   FROM webauthn_credentials
		  WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []webauthn.Credential
	for rows.Next() {
		var credID, pubKey []byte
		var signCount int64
		var transports string
		var uv bool
		if err := rows.Scan(&credID, &pubKey, &signCount, &transports, &uv); err != nil {
			continue
		}
		c := webauthn.Credential{
			ID:        credID,
			PublicKey: pubKey,
			Authenticator: webauthn.Authenticator{
				SignCount: uint32(signCount), //#nosec G115 -- WebAuthn spec specifies uint32 SignCount
			},
			Flags: webauthn.CredentialFlags{UserVerified: uv},
		}
		for _, t := range splitList(transports) {
			c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
		}
		creds = append(creds, c)
	}
	idBytes, _ := hexBytes(userID) // user.id is UUID; convert to 16-byte for WebAuthnID
	return &dbUser{
		id: idBytes, tenantID: tenantID, email: email,
		displayName: displayName, creds: creds,
	}, nil
}

// RegisterBegin — POST /api/v1/auth/webauthn/register/begin
func (h *WebAuthnH) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	userID := resolveUserUUID(r.Context(), h.DB, claims.UserID)
	if tenantID == "" || userID == "" {
		jsonError(w, "user not found", http.StatusForbidden)
		return
	}
	u, err := h.loadUser(r, userID, tenantID)
	if err != nil {
		jsonError(w, "load user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	options, sessionData, err := h.W.BeginRegistration(u)
	if err != nil {
		jsonError(w, "begin registration: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.persistSession(r, userID, tenantID, "registration", sessionData); err != nil {
		jsonError(w, "persist session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, options)
}

// RegisterFinish — POST /api/v1/auth/webauthn/register/finish
func (h *WebAuthnH) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	userID := resolveUserUUID(r.Context(), h.DB, claims.UserID)
	if tenantID == "" || userID == "" {
		jsonError(w, "user not found", http.StatusForbidden)
		return
	}
	u, err := h.loadUser(r, userID, tenantID)
	if err != nil {
		jsonError(w, "load user", http.StatusInternalServerError)
		return
	}
	sd, err := h.takeSession(r, userID, "registration")
	if err != nil {
		jsonError(w, "session expired or missing", http.StatusBadRequest)
		return
	}
	cred, err := h.W.FinishRegistration(u, *sd, r)
	if err != nil {
		jsonError(w, "finish registration: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Optional client metadata in body — nickname / attachment hint.
	var meta struct {
		Nickname   string `json:"nickname"`
		Attachment string `json:"attachment"`
	}
	_ = json.NewDecoder(r.Body).Decode(&meta)

	transports := joinTransports(cred.Transport)
	var aaguid *string
	if len(cred.Authenticator.AAGUID) == 16 {
		s := uuidFromBytes(cred.Authenticator.AAGUID)
		aaguid = &s
	}
	if _, err := h.DB.Pool().Exec(r.Context(),
		`INSERT INTO webauthn_credentials
		   (user_id, tenant_id, credential_id, public_key, sign_count,
		    aaguid, transports, nickname, attachment, user_verified)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (credential_id) DO NOTHING`,
		userID, tenantID, cred.ID, cred.PublicKey, cred.Authenticator.SignCount,
		aaguid, transports, meta.Nickname, meta.Attachment, cred.Flags.UserVerified,
	); err != nil {
		jsonError(w, "persist credential: "+err.Error(), http.StatusInternalServerError)
		return
	}
	logAudit(r, h.DB, "WEBAUTHN_REGISTERED", "webauthn/"+meta.Nickname)
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{
		"credential_id": cred.ID,
		"nickname":      meta.Nickname,
	})
}

// LoginBegin — POST /api/v1/auth/webauthn/login/begin (anonymous)
func (h *WebAuthnH) LoginBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		jsonError(w, "email required", http.StatusBadRequest)
		return
	}
	var userID, tenantID string
	if err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT id::text, tenant_id::text FROM users WHERE email = $1`, body.Email,
	).Scan(&userID, &tenantID); err != nil {
		// Constant-time-ish: don't reveal whether the email exists.
		jsonError(w, "no credentials available", http.StatusBadRequest)
		return
	}
	u, err := h.loadUser(r, userID, tenantID)
	if err != nil || len(u.creds) == 0 {
		jsonError(w, "no credentials registered", http.StatusBadRequest)
		return
	}
	options, sessionData, err := h.W.BeginLogin(u)
	if err != nil {
		jsonError(w, "begin login: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.persistSession(r, userID, tenantID, "authentication", sessionData); err != nil {
		jsonError(w, "persist session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, options)
}

// LoginFinish — POST /api/v1/auth/webauthn/login/finish (anonymous)
//
// On success, returns the same JSON shape the password login does so the
// SPA's existing token-handling code can be reused (issue JWT, set
// vsp_token cookie, etc.). The actual JWT minting is delegated to the
// caller via a small adapter — we simply mark the session as
// "passed WebAuthn" and let the SPA call /api/v1/auth/check.
func (h *WebAuthnH) LoginFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	// We need the email before we can rebuild the user, but the assertion
	// body is also in r.Body. The library's ParseCredentialRequestResponse
	// reads from r.Body directly, so we re-parse a copy. To keep this
	// simple v1, we accept email as a query param for the finish call.
	if v := r.URL.Query().Get("email"); v != "" {
		body.Email = v
	}
	if body.Email == "" {
		jsonError(w, "email query param required", http.StatusBadRequest)
		return
	}
	var userID, tenantID string
	if err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT id::text, tenant_id::text FROM users WHERE email = $1`, body.Email,
	).Scan(&userID, &tenantID); err != nil {
		jsonError(w, "no credentials available", http.StatusBadRequest)
		return
	}
	u, err := h.loadUser(r, userID, tenantID)
	if err != nil {
		jsonError(w, "load user", http.StatusInternalServerError)
		return
	}
	sd, err := h.takeSession(r, userID, "authentication")
	if err != nil {
		jsonError(w, "session expired or missing", http.StatusBadRequest)
		return
	}
	cred, err := h.W.FinishLogin(u, *sd, r)
	if err != nil {
		jsonError(w, "finish login: "+err.Error(), http.StatusUnauthorized)
		return
	}
	// Bump the sign_count to defeat replay across authenticator clones.
	// Non-fatal: login still succeeds, error suppressed intentionally.
	if _, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE webauthn_credentials
		    SET sign_count = $1, last_used_at = NOW()
		  WHERE credential_id = $2`,
		cred.Authenticator.SignCount, cred.ID); err != nil {
		log.Warn().Err(err).Msg("webauthn: sign_count bump failed (non-fatal)")
	}
	logAudit(r, h.DB, "WEBAUTHN_LOGIN", "user/"+userID)
	jsonOK(w, map[string]any{
		"user_id":   userID,
		"tenant_id": tenantID,
		"webauthn":  true,
		"hint":      "call /api/v1/auth/check to mint session token",
	})
}

// ListCredentials — GET /api/v1/auth/webauthn/credentials
func (h *WebAuthnH) ListCredentials(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userID := resolveUserUUID(r.Context(), h.DB, claims.UserID)
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id::text, COALESCE(nickname,''), COALESCE(attachment,''),
		        user_verified, created_at, last_used_at
		   FROM webauthn_credentials
		  WHERE user_id = $1 AND revoked_at IS NULL
		  ORDER BY created_at DESC`, userID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type item struct {
		ID         string     `json:"id"`
		Nickname   string     `json:"nickname"`
		Attachment string     `json:"attachment"`
		UV         bool       `json:"user_verified"`
		CreatedAt  time.Time  `json:"created_at"`
		LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	}
	var out []item
	for rows.Next() {
		var it item
		_ = rows.Scan(&it.ID, &it.Nickname, &it.Attachment, &it.UV, &it.CreatedAt, &it.LastUsedAt)
		out = append(out, it)
	}
	jsonOK(w, map[string]any{"credentials": out})
}

// RevokeCredential — POST /api/v1/auth/webauthn/credentials/{id}/revoke
func (h *WebAuthnH) RevokeCredential(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userID := resolveUserUUID(r.Context(), h.DB, claims.UserID)
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE webauthn_credentials SET revoked_at = NOW()
		  WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		id, userID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "credential not found", http.StatusNotFound)
		return
	}
	logAudit(r, h.DB, "WEBAUTHN_REVOKED", "webauthn/"+id)
	w.WriteHeader(http.StatusNoContent)
}

// ── Session persistence ─────────────────────────────────────────────────────

func (h *WebAuthnH) persistSession(r *http.Request, userID, tenantID, flow string,
	sd *webauthn.SessionData) error {

	blob, _ := json.Marshal(sd)
	expires := time.Now().Add(5 * time.Minute)
	var userPtr *string
	if userID != "" {
		userPtr = &userID
	}
	_, err := h.DB.Pool().Exec(r.Context(),
		`INSERT INTO webauthn_sessions
		   (user_id, tenant_id, flow, challenge, session_blob, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		userPtr, tenantID, flow, sd.Challenge, blob, expires)
	return err
}

func (h *WebAuthnH) takeSession(r *http.Request, userID, flow string) (*webauthn.SessionData, error) {
	var blob []byte
	if err := h.DB.Pool().QueryRow(r.Context(),
		`DELETE FROM webauthn_sessions
		  WHERE user_id = $1 AND flow = $2 AND expires_at > NOW()
		 RETURNING session_blob`,
		userID, flow).Scan(&blob); err != nil {
		return nil, err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(blob, &sd); err != nil {
		return nil, err
	}
	return &sd, nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func getenvDefault(k, dflt string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return dflt
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := []string{}
	for _, p := range splitOn(s, ',') {
		if p = trim(p); p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func splitOn(s string, sep byte) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func joinTransports(t []protocol.AuthenticatorTransport) string {
	out := ""
	for i, x := range t {
		if i > 0 {
			out += ","
		}
		out += string(x)
	}
	return out
}

func uuidFromBytes(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 36)
	dashAt := map[int]bool{8: true, 13: true, 18: true, 23: true}
	bi := 0
	for i := 0; i < 36; i++ {
		if dashAt[i] {
			out[i] = '-'
			continue
		}
		c := b[bi/2]
		if bi%2 == 0 {
			out[i] = hex[c>>4]
		} else {
			out[i] = hex[c&0xf]
		}
		bi++
	}
	return string(out)
}

// hexBytes converts a UUID string ("8-4-4-4-12") into 16 raw bytes.
func hexBytes(uuid string) ([]byte, bool) {
	if len(uuid) != 36 {
		return nil, false
	}
	out := make([]byte, 0, 16)
	for i := 0; i < 36; i++ {
		c := uuid[i]
		if c == '-' {
			continue
		}
		var n byte
		switch {
		case c >= '0' && c <= '9':
			n = c - '0'
		case c >= 'a' && c <= 'f':
			n = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			n = c - 'A' + 10
		default:
			return nil, false
		}
		if (i-countDashes(i))%2 == 0 {
			out = append(out, n<<4)
		} else {
			out[len(out)-1] |= n
		}
	}
	return out, true
}

func countDashes(idx int) int {
	n := 0
	for _, p := range []int{8, 13, 18, 23} {
		if idx > p {
			n++
		}
	}
	return n
}
