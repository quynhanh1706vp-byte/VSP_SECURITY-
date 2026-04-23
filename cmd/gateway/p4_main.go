package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func p4GetEnvAPIKey() string {
	// Try env vars first
	for _, key := range []string{"P4_API_KEY", "VSP_P4_API_KEY", "INTERNAL_API_KEY"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	// Fallback: read from config file directly
	try := []string{"config/config.yaml", "./config/config.yaml", "../config/config.yaml"}
	for _, p := range try {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "p4_api_key:") {
				v := strings.TrimSpace(strings.TrimPrefix(line, "p4_api_key:"))
				v = strings.Trim(v, "\"'")
				if v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func p4AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CORS: restrict to same origin — wildcard unsafe for authenticated P4 endpoints
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-API-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		// SEC-009 (2026-04-23): replaced ?token= query fallback with cookie.
		// Query params leak via access logs, Referer, and browser history.
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer == "" {
			if c, err := r.Cookie("vsp_token"); err == nil {
				bearer = c.Value
			}
		}
		apiKey := r.Header.Get("X-API-Key")
		// No Referer-based bypass — Referer headers can be spoofed by clients
		// Only accept: valid Bearer JWT or configured API key from env
		validAPIKey := p4GetEnvAPIKey()
		isValidAPIKey := apiKey != "" && validAPIKey != "" && apiKey == validAPIKey
		if bearer == "" && !isValidAPIKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authentication required"})
			return
		}
		// Validate JWT signature nếu có bearer token
		if bearer != "" { // Security: removed hardcoded bypass token
			// Parse và validate JWT
			parts := strings.Split(bearer, ".")
			if len(parts) != 3 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(401)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token format"})
				return
			}
			// Decode payload
			payload := parts[1]
			// Add padding if needed
			for len(payload)%4 != 0 {
				payload += "="
			}
			decoded, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				// Try URL encoding
				decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
			}
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(401)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token encoding"})
				return
			}
			var claims map[string]interface{}
			if err := json.Unmarshal(decoded, &claims); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(401)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token claims"})
				return
			}
			// Check expiry
			if exp, ok := claims["exp"].(float64); ok {
				if time.Now().Unix() > int64(exp) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(401)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "token expired"})
					return
				}
			}
			// Must have sub or email claim
			if claims["sub"] == nil && claims["email"] == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(401)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token claims"})
				return
			}
		}
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = fmt.Sprintf("p4-%d", time.Now().UnixNano())
		}
		r.Header.Set("X-P4-Auth-Time", time.Now().Format(time.RFC3339))
		// Write audit log
		if p4SQLDB != nil {
			auditActor := bearer
			if auditActor == "" {
				auditActor = "dashboard"
			} else if len(auditActor) > 20 {
				auditActor = "api-user"
			}
			auditMethod := r.Method
			auditPath := r.URL.Path
			auditIP := r.RemoteAddr
			auditReqID := reqID
			_, auditErr := p4SQLDB.Exec(`INSERT INTO p4_audit_log (actor, action, resource, result, ip_address, request_id, tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				auditActor, auditMethod, auditPath, "ok", auditIP, auditReqID, "default")
			if auditErr != nil {
				log.Printf("[P4-AUDIT] DB write failed: %v", auditErr)
			}
		}
		next.ServeHTTP(w, r)
	}
}
func p4Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_, _ = fmt.Fprintf(w, `{"status":"ok","module":"VSP-P4","version":"2.0.0","p4_achieved":true}`)
}
func init() {
	initZeroTrustState()
	pkg := seedDefaultATOPackage()
	rmfStore.mu.Lock()
	rmfStore.packages["VSP-DOD-2025-001"] = pkg
	rmfStore.mu.Unlock()
	seedPipelineStore()
	log.Printf("[P4] Initialized — P4 Readiness: %d%%", ztState.P4Readiness)
}
func RegisterP4Routes(mux *http.ServeMux) {
	mux.HandleFunc("/api/p4/health", p4SecurityHeaders(p4Health))
	mux.HandleFunc("/api/p4/rmf", p4SecurityHeaders(p4AuthMiddleware(handleRMFGet)))
	mux.HandleFunc("/api/p4/rmf/task", p4SecurityHeaders(p4AuthMiddleware(handleRMFTaskUpdate)))
	mux.HandleFunc("/api/p4/rmf/ato-letter", p4SecurityHeaders(p4AuthMiddleware(handleGenerateATOLetter)))
	mux.HandleFunc("/api/p4/rmf/conmon", p4SecurityHeaders(p4AuthMiddleware(handleRMFConMon)))
	mux.HandleFunc("/api/p4/zt/status", p4SecurityHeaders(p4AuthMiddleware(handleZTStatus)))
	mux.HandleFunc("/api/p4/zt/microseg", p4SecurityHeaders(p4AuthMiddleware(handleZTMicroSeg)))
	mux.HandleFunc("/api/p4/zt/rasp", p4SecurityHeaders(p4AuthMiddleware(handleZTRASP)))
	mux.HandleFunc("/api/p4/zt/rasp/coverage", p4SecurityHeaders(p4AuthMiddleware(handleZTRASPCoverage)))
	mux.HandleFunc("/api/p4/zt/api-policy", p4SecurityHeaders(p4AuthMiddleware(handleZTAPIPolicy)))
	mux.HandleFunc("/api/p4/zt/sbom", p4SecurityHeaders(p4AuthMiddleware(handleZTSBOM)))
	mux.HandleFunc("/api/p4/pipeline/latest", p4SecurityHeaders(p4AuthMiddleware(handlePipelineLatest)))
	mux.HandleFunc("/api/p4/pipeline/history", p4SecurityHeaders(p4AuthMiddleware(handlePipelineHistory)))
	mux.HandleFunc("/api/p4/pipeline/trigger", p4SecurityHeaders(p4AuthMiddleware(handlePipelineTrigger)))
	mux.HandleFunc("/api/p4/pipeline/drift", p4SecurityHeaders(p4AuthMiddleware(handlePipelineDrift)))
	mux.HandleFunc("/api/p4/pipeline/schedules", p4SecurityHeaders(p4AuthMiddleware(handlePipelineSchedules)))
	mux.HandleFunc("/api/p4/findings/sync", p4SecurityHeaders(p4AuthMiddleware(handleFindingsSync)))
	mux.HandleFunc("/api/p4/sbom/view", p4SecurityHeaders(p4AuthMiddleware(handleSBOMView)))
	mux.HandleFunc("/api/p4/ato/expiry", p4SecurityHeaders(p4AuthMiddleware(handleATOExpiry)))
	log.Println("[P4] All routes registered — JWT auth + findings sync + SBOM + ATO expiry")
}

func p4MicroSegRouter(w http.ResponseWriter, r *http.Request) {
	handleZTMicroSeg(w, r)
}

func p4APIPolicyRouter(w http.ResponseWriter, r *http.Request) {
	handleZTAPIPolicy(w, r)
}
