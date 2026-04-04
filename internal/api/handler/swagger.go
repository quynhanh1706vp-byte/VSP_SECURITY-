package handler

import (
	"encoding/json"
	"os"
	"strings"
	"net/http"
	"time"
)

// OpenAPI 3.0 spec — generated from handler definitions
type openAPISpec struct {
	OpenAPI string            `json:"openapi"`
	Info    map[string]any    `json:"info"`
	Servers []map[string]any  `json:"servers"`
	Paths   map[string]any    `json:"paths"`
	Components map[string]any `json:"components"`
}

var cachedSpec []byte
var cachedAt time.Time

// GET /api/docs/openapi.json
func SwaggerJSON(w http.ResponseWriter, r *http.Request) {
	if cachedSpec != nil && time.Since(cachedAt) < time.Hour {
		w.Header().Set("Content-Type", "application/json")
		w.Write(cachedSpec)
		return
	}

	spec := buildSpec(r)
	b, _ := json.MarshalIndent(spec, "", "  ")
	cachedSpec = b
	cachedAt = time.Now()

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// GET /api/docs  — Swagger UI HTML (chỉ cho localhost và internal)
func SwaggerUI(w http.ResponseWriter, r *http.Request) {
	// Restrict swagger UI — chỉ cho internal/dev access
	// Trong production, remove route này hoặc thêm IP whitelist
	serverEnv := os.Getenv("SERVER_ENV")
	if serverEnv == "production" {
		remoteIP := r.RemoteAddr
		if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
			remoteIP = remoteIP[:idx]
		}
		allowedIPs := map[string]bool{
			"127.0.0.1": true, "::1": true, "[::1]": true,
		}
		if !allowedIPs[remoteIP] {
			http.Error(w, "API docs not available in production", http.StatusForbidden)
			return
		}
	}
	host := r.Host
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
  <title>VSP API — Swagger UI</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" >
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"> </script>
<script>
window.onload = function() {
  SwaggerUIBundle({
    url: "http://` + host + `/api/docs/openapi.json",
    dom_id: '#swagger-ui',
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
    layout: "BaseLayout",
    deepLinking: true,
    defaultModelsExpandDepth: 1,
    defaultModelExpandDepth: 1,
  })
}
</script>
</body>
</html>`))
}

func buildSpec(r *http.Request) openAPISpec {
	scheme := "http"
	if r.TLS != nil { scheme = "https" }
	return openAPISpec{
		OpenAPI: "3.0.3",
		Info: map[string]any{
			"title":       "VSP Security Platform API",
			"description": "Enterprise security scanning platform — Go v0.4.1",
			"version":     "0.4.1",
			"contact":     map[string]string{"name": "VSP Engineering"},
		},
		Servers: []map[string]any{
			{"url": scheme + "://" + r.Host, "description": "Current server"},
		},
		Components: map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
			},
		},
		Paths: map[string]any{
			"/api/v1/auth/login": map[string]any{
				"post": map[string]any{
					"tags":    []string{"Auth"},
					"summary": "Login and get JWT token",
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{
									"type": "object",
									"properties": map[string]any{
										"email":    map[string]string{"type": "string"},
										"password": map[string]string{"type": "string"},
									},
								},
							},
						},
					},
					"responses": map[string]any{"200": map[string]any{"description": "JWT token"}},
				},
			},
			"/api/v1/vsp/run": map[string]any{
				"post": map[string]any{
					"tags":    []string{"Scan"},
					"summary": "Trigger a security scan",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{
									"type": "object",
									"properties": map[string]any{
										"mode":    map[string]any{"type": "string", "enum": []string{"SAST","SCA","SECRETS","IAC","DAST","FULL"}},
										"profile": map[string]any{"type": "string", "enum": []string{"FAST","EXT","AGGR","PREMIUM","FULL","FULL_SOC"}},
										"src":     map[string]string{"type": "string"},
										"url":     map[string]string{"type": "string"},
									},
								},
							},
						},
					},
					"responses": map[string]any{"202": map[string]any{"description": "Run queued"}},
				},
			},
			"/api/v1/vsp/run/{rid}": map[string]any{
				"get": map[string]any{
					"tags":    []string{"Scan"},
					"summary": "Get scan run status",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"parameters": []map[string]any{{"name": "rid", "in": "path", "required": true, "schema": map[string]string{"type": "string"}}},
					"responses": map[string]any{"200": map[string]any{"description": "Run object"}},
				},
			},
			"/api/v1/vsp/findings": map[string]any{
				"get": map[string]any{
					"tags":    []string{"Findings"},
					"summary": "List findings",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"parameters": []map[string]any{
						{"name": "severity", "in": "query", "schema": map[string]any{"type": "string", "enum": []string{"CRITICAL","HIGH","MEDIUM","LOW","INFO"}}},
						{"name": "tool",     "in": "query", "schema": map[string]string{"type": "string"}},
						{"name": "limit",    "in": "query", "schema": map[string]string{"type": "integer"}},
						{"name": "offset",   "in": "query", "schema": map[string]string{"type": "integer"}},
					},
					"responses": map[string]any{"200": map[string]any{"description": "Findings list"}},
				},
			},
			"/api/v1/vsp/findings/summary": map[string]any{
				"get": map[string]any{
					"tags":    []string{"Findings"},
					"summary": "Findings severity summary (latest run by default)",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"parameters": []map[string]any{
						{"name": "scope",  "in": "query", "schema": map[string]any{"type": "string", "enum": []string{"latest","all"}}},
						{"name": "run_id", "in": "query", "schema": map[string]string{"type": "string"}},
					},
					"responses": map[string]any{"200": map[string]any{"description": "Summary counts"}},
				},
			},
			"/api/v1/compliance/oscal/ar": map[string]any{
				"get": map[string]any{"tags": []string{"Compliance"}, "summary": "OSCAL Assessment Result", "security": []map[string]any{{"bearerAuth": []string{}}}, "responses": map[string]any{"200": map[string]any{"description": "OSCAL AR JSON"}}},
			},
			"/api/v1/compliance/oscal/poam": map[string]any{
				"get": map[string]any{"tags": []string{"Compliance"}, "summary": "OSCAL POA&M", "security": []map[string]any{{"bearerAuth": []string{}}}, "responses": map[string]any{"200": map[string]any{"description": "OSCAL POA&M JSON"}}},
			},
			"/api/v1/vsp/sla_tracker": map[string]any{
				"get": map[string]any{"tags": []string{"SLA"}, "summary": "SLA breach tracking by severity", "security": []map[string]any{{"bearerAuth": []string{}}}, "responses": map[string]any{"200": map[string]any{"description": "SLA data"}}},
			},
			"/api/v1/vsp/sandbox/test-fire": map[string]any{
				"post": map[string]any{"tags": []string{"Sandbox"}, "summary": "Fire test webhook event", "security": []map[string]any{{"bearerAuth": []string{}}}, "responses": map[string]any{"200": map[string]any{"description": "Event fired"}}},
			},
			"/metrics": map[string]any{
				"get": map[string]any{"tags": []string{"Observability"}, "summary": "Prometheus metrics (no auth)", "responses": map[string]any{"200": map[string]any{"description": "Prometheus text format"}}},
			},
			"/health": map[string]any{
				"get": map[string]any{"tags": []string{"Observability"}, "summary": "Health check", "responses": map[string]any{"200": map[string]any{"description": "OK"}}},
			},
		},
	}
}
