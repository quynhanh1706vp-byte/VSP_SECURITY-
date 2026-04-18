package handler

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

var sseJWTSecret string

func SetJWTSecret(s string) { sseJWTSecret = s }

// WSHub broadcasts scan events to all connected dashboard clients.
type WSHub struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
}

var Hub = &WSHub{clients: make(map[chan []byte]struct{})}

func (h *WSHub) Broadcast(msg []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (h *WSHub) register(ch chan []byte)   { h.mu.Lock(); h.clients[ch] = struct{}{}; h.mu.Unlock() }
func (h *WSHub) unregister(ch chan []byte) { h.mu.Lock(); delete(h.clients, ch); h.mu.Unlock() }

// GET /api/v1/events — Server-Sent Events (SSE) stream
func SSEHandler(w http.ResponseWriter, r *http.Request) {
	rawToken := r.URL.Query().Get("token")
	if rawToken == "" {
		rawToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if rawToken == "" || sseJWTSecret == "" {
		http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
		return
	}
	_, jwtErr := jwt.ParseWithClaims(rawToken, &jwt.MapClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(sseJWTSecret), nil
		})
	if jwtErr != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan []byte, 8)
	Hub.register(ch)
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
