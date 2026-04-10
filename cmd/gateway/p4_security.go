package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
)

func p4SecurityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate nonce for CSP
		nonce := make([]byte, 16)
		rand.Read(nonce)
		nonceStr := hex.EncodeToString(nonce)

		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Request ID for audit trail
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			b := make([]byte, 8)
			rand.Read(b)
			reqID = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-ID", reqID)
		_ = nonceStr

		// Log P4 API access for audit trail
		if strings.HasPrefix(r.URL.Path, "/api/p4/") {
			// Note: X-Auth-User is client-controlled — for audit only, not security decisions
			authUser := r.Header.Get("X-Auth-User") + "(client-header)"
			if authUser == "(client-header)" {
				authUser = "anonymous"
			}
			log.Printf("[P4-AUDIT] %s %s by %s from %s req=%s",
				r.Method, r.URL.Path, authUser, r.RemoteAddr, reqID)
			// Write to audit DB — capture vars before goroutine
			if p4SQLDB != nil {
				auditActor := authUser
				auditAction := r.Method
				auditResource := r.URL.Path
				auditIP := r.RemoteAddr
				auditReqID := reqID
				_, auditErr := p4SQLDB.Exec(`INSERT INTO p4_audit_log (actor, action, resource, result, ip_address, request_id, tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
					auditActor, auditAction, auditResource, "ok", auditIP, auditReqID, "default")
				if auditErr != nil {
					log.Printf("[P4-AUDIT-DB] Write failed: %v", auditErr)
				} else {
					log.Printf("[P4-AUDIT-DB] Written: %s %s by %s", auditAction, auditResource, auditActor)
				}
			}
		}

		next(w, r)
	}
}

// Input validation
func validateP4Input(r *http.Request) bool {
	// Block oversized requests
	if r.ContentLength > 1024*1024 { // 1MB max
		return false
	}
	// Block suspicious paths
	path := r.URL.Path
	if strings.Contains(path, "..") || strings.Contains(path, "//") {
		return false
	}
	return true
}

// suppress U1000 — validateP4Input used in future handlers
var _ = validateP4Input
