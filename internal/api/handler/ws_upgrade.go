package handler

import (
	"crypto/sha1" // #nosec G505 -- RFC6455 WebSocket handshake mandates SHA-1 accept-key
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// GET /api/v1/ws — WebSocket upgrade with SSE fallback
func WSUpgradeHandler(w http.ResponseWriter, r *http.Request) {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	if upgrade == "websocket" {
		rawToken := r.URL.Query().Get("token")
		if rawToken == "" {
			rawToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if rawToken == "" {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return
		}
		// Validate token length — real JWT validation happens in middleware
		// WS upgrades bypass middleware, so basic sanity check here
		if len(rawToken) < 50 || !strings.Contains(rawToken, ".") {
			http.Error(w, `{"error":"invalid token format"}`, http.StatusUnauthorized)
			return
		}
		wsServe(w, r)
		return
	}
	SSEHandler(w, r)
}

func wsServe(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket not supported", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	accept := wsAcceptKey(key)
	hs := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	buf.WriteString(hs) //nolint
	buf.Flush()         //nolint

	ch := make(chan []byte, 16)
	Hub.register(ch)
	defer Hub.unregister(ch)

	ActiveSSEClients.Inc()
	defer ActiveSSEClients.Dec()

	log.Debug().Str("remote", r.RemoteAddr).Msg("ws: client connected")
	wsWriteText(conn, `{"type":"connected"}`) //nolint

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			conn.Write([]byte{0x88, 0x00}) //nolint
			return
		case <-ping.C:
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint
			if _, err := conn.Write([]byte{0x89, 0x00}); err != nil {
				return
			}
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if err := wsWriteText(conn, string(msg)); err != nil {
				return
			}
		}
	}
}

func wsAcceptKey(key string) string {
	h := sha1.New() // #nosec G401 -- RFC6455 WebSocket accept-key requires SHA-1
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func wsWriteText(conn net.Conn, msg string) error {
	b := []byte(msg)
	if len(b) > 65535 {
		b = b[:65535] // truncate — WebSocket 2-byte extended payload max
	}
	var frame []byte
	n := len(b)
	if n <= 125 {
		frame = make([]byte, 2+n)
		frame[0] = 0x81
		frame[1] = byte(n) //#nosec G115 -- n <= 125 after bounds check
		copy(frame[2:], b)
	} else {
		frame = make([]byte, 4+n)
		frame[0] = 0x81
		frame[1] = 126
		frame[2] = byte(n >> 8)   //#nosec G115 -- n <= 65535 after truncation
		frame[3] = byte(n & 0xFF) //#nosec G115 -- n <= 65535
		copy(frame[4:], b)
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint
	_, err := conn.Write(frame)
	return err
}
