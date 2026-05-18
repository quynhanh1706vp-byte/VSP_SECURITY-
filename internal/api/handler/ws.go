package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

var sseJWTSecret string

func SetJWTSecret(s string) { sseJWTSecret = s }

// tenantResolver normalises a JWT tenant claim (which may be a slug
// like "default") to the UUID that broadcast messages carry. main.go
// wires this from the DB; identity by default (so unit tests stay
// hermetic).
var tenantResolver = func(claim string) string { return claim }

// SetSSETenantResolver wires the slug→UUID lookup for SSE subscriber
// scoping. Call once from gateway startup; safe before any client
// connects.
func SetSSETenantResolver(fn func(string) string) {
	if fn != nil {
		tenantResolver = fn
	}
}

// WSHub broadcasts scan events to connected dashboard clients with
// tenant scoping.
//
// L5 2026-05-09: pre-fix Broadcast fan-out went to every connected
// client regardless of tenant — proven by scripts/test-l5-advanced.sh
// 6.1.1 which captured tenant B's scan_complete in tenant A's stream.
// The fix tracks each subscriber's tenant ID at register time, and
// Broadcast inspects the JSON payload's tenant_id field to route
// only to matching subscribers. Messages without a tenant_id (system
// events) still go to everyone.
type WSHub struct {
	mu      sync.RWMutex
	clients map[chan []byte]string // chan → tenantID ("" = global subscriber)
}

var Hub = &WSHub{clients: make(map[chan []byte]string)}

// Broadcast routes msg by tenant_id when present in the JSON payload,
// or globally when not. Per-subscriber send is non-blocking.
func (h *WSHub) Broadcast(msg []byte) {
	target := extractTenantID(msg)
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch, tid := range h.clients {
		// Routing rule:
		//   - msg has no tenant_id   → send to everyone (system event)
		//   - msg has tenant_id      → only subscribers of that tenant
		//                              AND global ("") subscribers (none
		//                              today, but kept for ops dashboards
		//                              that may want cluster-wide view)
		if target != "" && tid != "" && tid != target {
			continue
		}
		select {
		case ch <- msg:
		default:
		}
	}
}

// extractTenantID does a cheap scan for "tenant_id":"<uuid>" in the
// JSON payload. Falls back to a strict json.Unmarshal only on the
// fast-path miss so the hot loop stays allocation-free for the common
// case.
func extractTenantID(msg []byte) string {
	// Cheap substring scan first.
	if i := strings.Index(string(msg), `"tenant_id":"`); i >= 0 {
		rest := string(msg)[i+len(`"tenant_id":"`):]
		if j := strings.Index(rest, `"`); j > 0 {
			return rest[:j]
		}
	}
	// Slow path: structured parse (handles spaces, escaped quotes).
	var probe struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(msg, &probe); err == nil {
		return probe.TenantID
	}
	return ""
}

func (h *WSHub) register(ch chan []byte, tenantID string) {
	h.mu.Lock()
	h.clients[ch] = tenantID
	h.mu.Unlock()
}
func (h *WSHub) unregister(ch chan []byte) { h.mu.Lock(); delete(h.clients, ch); h.mu.Unlock() }

// GET /api/v1/events — Server-Sent Events (SSE) stream
func SSEHandler(w http.ResponseWriter, r *http.Request) {
	// SEC-009 (2026-04-23): auth is handled by auth.Middleware mounted
	// on this route in gateway/main.go. Claims are already in context.
	// The token itself is re-parsed below only to validate JWT rotation,
	// which is already done by the middleware — consider removing this
	// secondary validation in a follow-up PR once SSE tests land.
	rawToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if rawToken == "" {
		if c, err := r.Cookie("vsp_token"); err == nil {
			rawToken = c.Value
		}
	}
	if rawToken == "" || sseJWTSecret == "" {
		http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
		return
	}
	// VSP-SEC (JWT rotation): try primary + old secret (if set)
	secrets := []string{sseJWTSecret}
	if old := os.Getenv("JWT_SECRET_OLD"); old != "" && old != sseJWTSecret {
		secrets = append(secrets, old)
	}
	var jwtErr error
	var tenantID string
	for _, s := range secrets {
		var parsedClaims jwt.MapClaims
		_, jwtErr = jwt.ParseWithClaims(rawToken, &parsedClaims,
			func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(s), nil
			})
		if jwtErr == nil {
			// L5 fix: subscribe to events scoped to THIS tenant. Pre-fix
			// the parsed claims were thrown away — every subscriber got
			// every event. Read either the canonical "tid" or the
			// alias "tenant_id" used by mint_jwt scripts.
			if v, ok := parsedClaims["tid"].(string); ok && v != "" {
				tenantID = v
			} else if v, ok := parsedClaims["tenant_id"].(string); ok {
				tenantID = v
			}
			break
		}
	}
	if jwtErr != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Resolve slug → UUID. Broadcast messages carry the UUID (from the
	// runs.tenant_id column) so subscriber scoping must match.
	subscriberTenantID := tenantResolver(tenantID)

	ch := make(chan []byte, 8)
	Hub.register(ch, subscriberTenantID)
	defer Hub.unregister(ch)

	// Send initial ping
	_, _ = w.Write([]byte("data: {\"type\":\"connected\"}\n\n")) //nolint
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	log.Debug().Str("remote", r.RemoteAddr).Msg("sse: client connected")
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			// keepalive ping
			_, _ = w.Write([]byte(": ping\n\n")) //nolint
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case msg := <-ch:
			_, _ = w.Write(append([]byte("data: "), append(msg, '\n', '\n')...)) //nolint
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}
}
