// Package handler — HTTP handlers for VSP Deep Packet Analysis endpoints.
// Registers onto chi router inside gateway/main.go.
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vsp/platform/internal/netcap"
)

// NetCapHandler handles all /api/v1/netcap/* endpoints.
type NetCapHandler struct {
	Engine *netcap.Engine
}

// NewNetCapHandler creates a handler with a shared Engine.
func NewNetCapHandler(e *netcap.Engine) *NetCapHandler {
	return &NetCapHandler{Engine: e}
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/interfaces
// Returns list of available network interfaces.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) Interfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := h.Engine.GetInterfaces()
	if err != nil {
		jsonError(w, "failed to list interfaces: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"interfaces": ifaces,
		"default":    pickDefaultInterface(ifaces),
	})
}

// ─────────────────────────────────────────────────────────────
// POST /api/v1/netcap/start
// Starts packet capture on specified interface.
// Body: {"interface":"eth0","bpf_filter":"tcp port 80","snaplen":1500}
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) Start(w http.ResponseWriter, r *http.Request) {
	var cfg netcap.CaptureConfig
	if !decodeJSON(w, r, &cfg) {
		// Defaults if no body
		cfg.Interface = "any"
		cfg.SnapLen = 1500
	}

	if err := h.Engine.Start(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonOK(w, map[string]interface{}{
		"status":     "capturing",
		"interface":  cfg.Interface,
		"filter":     cfg.BPFFilter,
		"started_at": time.Now(),
	})
}

// ─────────────────────────────────────────────────────────────
// POST /api/v1/netcap/stop
// Stops packet capture.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) Stop(w http.ResponseWriter, r *http.Request) {
	h.Engine.Stop()
	jsonOK(w, map[string]interface{}{
		"status":     "stopped",
		"stopped_at": time.Now(),
	})
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/stats
// Returns live KPI snapshot.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) Stats(w http.ResponseWriter, r *http.Request) {
	stats := h.Engine.GetStats()
	jsonOK(w, stats)
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/flows
// Returns active IP flows with optional filters.
// Query: ?limit=100&proto=TCP&flags=SYN
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) Flows(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	proto := r.URL.Query().Get("proto")
	flags := r.URL.Query().Get("flags")

	flows := h.Engine.GetFlows(limit, proto, flags)
	jsonOK(w, map[string]interface{}{
		"flows": flows,
		"count": len(flows),
	})
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/anomalies
// Returns detected anomalies, newest first.
// Query: ?limit=50
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) Anomalies(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	anoms := h.Engine.GetAnomalies(limit)
	jsonOK(w, map[string]interface{}{
		"anomalies": anoms,
		"count":     len(anoms),
	})
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/tcp-flags
// Returns TCP flag distribution counters.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) TCPFlags(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, h.Engine.GetTCPFlags())
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/proto-breakdown
// Returns L7 protocol breakdown by traffic volume.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) ProtoBreakdown(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"protocols": h.Engine.GetProtoBreakdown(),
	})
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/l7/http
// Returns decoded HTTP requests.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) L7HTTP(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	reqs := h.Engine.GetHTTPRequests(limit)
	jsonOK(w, map[string]interface{}{
		"requests": reqs,
		"count":    len(reqs),
	})
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/l7/dns
// Returns decoded DNS queries.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) L7DNS(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	queries := h.Engine.GetDNSQueries(limit)
	jsonOK(w, map[string]interface{}{
		"queries": queries,
		"count":   len(queries),
	})
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/l7/sql
// Returns decoded PostgreSQL wire events.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) L7SQL(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	evts := h.Engine.GetSQLEvents(limit)
	jsonOK(w, map[string]interface{}{
		"events": evts,
		"count":  len(evts),
	})
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/l7/tls
// Returns decoded TLS sessions with JA3 fingerprints.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) L7TLS(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	sessions := h.Engine.GetTLSSessions(limit)
	jsonOK(w, map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/l7/grpc
// Returns decoded gRPC frame events.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) L7GRPC(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	evts := h.Engine.GetGRPCEvents(limit)
	jsonOK(w, map[string]interface{}{
		"events": evts,
		"count":  len(evts),
	})
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/export/flows.csv
// Downloads current flows as CSV.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) ExportFlowsCSV(w http.ResponseWriter, r *http.Request) {
	data := h.Engine.ExportFlowsCSV()
	filename := fmt.Sprintf("vsp-flows-%s.csv", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/export/anomalies.json
// Downloads anomalies as JSON.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) ExportAnomaliesJSON(w http.ResponseWriter, r *http.Request) {
	data := h.Engine.ExportAnomaliesJSON()
	filename := fmt.Sprintf("vsp-anomalies-%s.json", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/stream
// SSE endpoint — streams stats + anomaly events in real-time.
// EventSource compatible.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) Stream(w http.ResponseWriter, r *http.Request) {
	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx: disable buffering
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Send initial state
	stats := h.Engine.GetStats()
	sendSSE(w, flusher, "stats", stats)

	// Subscribe to engine events
	ch := h.Engine.Subscribe()
	defer h.Engine.Unsubscribe(ch)

	// Heartbeat ticker — keeps connection alive through proxies
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

// ─────────────────────────────────────────────────────────────
// GET /api/v1/netcap/full
// Returns everything in one response — for initial page load.
// ─────────────────────────────────────────────────────────────

func (h *NetCapHandler) Full(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)

	jsonOK(w, map[string]interface{}{
		"stats":           h.Engine.GetStats(),
		"flows":           h.Engine.GetFlows(limit, "", ""),
		"anomalies":       h.Engine.GetAnomalies(limit),
		"tcp_flags":       h.Engine.GetTCPFlags(),
		"proto_breakdown": h.Engine.GetProtoBreakdown(),
		"http_requests":   h.Engine.GetHTTPRequests(limit),
		"dns_queries":     h.Engine.GetDNSQueries(limit),
		"sql_events":      h.Engine.GetSQLEvents(limit),
		"tls_sessions":    h.Engine.GetTLSSessions(limit),
		"grpc_events":     h.Engine.GetGRPCEvents(limit),
	})
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

func sendSSE(w http.ResponseWriter, f http.Flusher, event string, data interface{}) {
	b, _ := json.Marshal(map[string]interface{}{"event": event, "data": data})
	fmt.Fprintf(w, "data: %s\n\n", b)
	f.Flush()
}

func pickDefaultInterface(ifaces []string) string {
	preferred := []string{"eth0", "ens3", "ens4", "enp0s3", "wlp59s0"}
	for _, p := range preferred {
		for _, i := range ifaces {
			if i == p {
				return i
			}
		}
	}
	// Avoid loopback as default
	for _, i := range ifaces {
		if i != "lo" && !strings.HasPrefix(i, "docker") && !strings.HasPrefix(i, "br-") {
			return i
		}
	}
	if len(ifaces) > 0 {
		return ifaces[0]
	}
	return "any"
}
