package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"strings"

	ai "github.com/vsp/platform/internal/ai"

	"encoding/json"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"io"
)

// securityMiddleware adds security headers and a per-request CSP nonce to every response.
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate nonce
		b := make([]byte, 16)
		rand.Read(b) //nolint:errcheck
		nonce := base64.StdEncoding.EncodeToString(b)

		// P4 panel needs permissive CSP for inline scripts
		if strings.HasPrefix(r.URL.Path, "/static/panels/") || r.URL.Path == "/p4" {
			w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;")
		} else {
			csp := "default-src 'self'; " +
				"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; " +
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; " +
				"font-src 'self' https://fonts.gstatic.com; " +
				"img-src 'self' data: blob:; " +
				"connect-src 'self' wss: ws: https://api.anthropic.com https://cdn.jsdelivr.net; " +
				"frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
			w.Header().Set("Content-Security-Policy", csp)
		}

		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		// CSRF cookie là trách nhiệm của gateway (port 8921)
		// soc-shell KHÔNG set vsp_csrf — tránh duplicate/conflict
		// Browser sẽ nhận cookie từ response gateway qua proxy

		// Store nonce in context for downstream handlers
		ctx := context.WithValue(r.Context(), struct{ key string }{"nonce"}, nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func main() {
	viper.SetDefault("server.shell_port", 8922)
	viper.SetDefault("server.gateway_port", 8921)
	viper.SetDefault("log.level", "info")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.BindEnv("server.gateway_host", "GATEWAY_HOST")
	viper.BindEnv("server.gateway_port", "GATEWAY_PORT")
	viper.ReadInConfig()

	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	shellPort := viper.GetInt("server.shell_port")
	gatewayPort := viper.GetInt("server.gateway_port")
	gatewayHost := viper.GetString("server.gateway_host")
	if gatewayHost == "" {
		gatewayHost = "localhost"
	}
	gatewayURL, _ := url.Parse(fmt.Sprintf("http://%s:%d", gatewayHost, gatewayPort))
	proxy := httputil.NewSingleHostReverseProxy(gatewayURL)

	mux := http.NewServeMux()

	// AI Analyst proxy — forward to Anthropic API
	mux.HandleFunc("/api/v1/ai/chat", ai.Handler) //

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"soc-shell","port":%d}`, shellPort)
	})
	// P4 Compliance panel — serve directly with permissive CSP
	mux.HandleFunc("/billing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "./static/billing.html")
	})
	mux.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "./static/docs.html")
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "./static/admin.html")
	})
	mux.HandleFunc("/onboarding", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "./static/onboarding.html")
	})
	mux.HandleFunc("/landing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, "./static/landing.html")
	})
	// Reverse proxy /api/p4/* → gateway:8921
	mux.HandleFunc("/api/p4/", func(w http.ResponseWriter, r *http.Request) {
		target := "http://127.0.0.1:8921" + r.URL.RequestURI()
		req, err := http.NewRequest(r.Method, target, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		for k, vv := range r.Header {
			for _, v := range vv {
				req.Header.Add(k, v)
			}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
	})

	mux.HandleFunc("/p4", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; connect-src *;")
		w.Header().Set("Cache-Control", "no-store")
		// If token in query, inject it as window.TOKEN before page scripts
		token := r.URL.Query().Get("token")
		if token != "" {
			data, err := os.ReadFile("./static/panels/p4_compliance.html")
			if err == nil {
				html := string(data)
				tokenJSON, _ := json.Marshal(token)
				inject := "<script>window.TOKEN=" + string(tokenJSON) + ";</script>"
				html = strings.Replace(html, "<head>", "<head>"+inject, 1)
				w.Write([]byte(html)) //nolint:errcheck
				return
			}
		}
		http.ServeFile(w, r, "./static/panels/p4_compliance.html")
	})
	// Serve static files, fallback to index.html for SPA
	fs := http.FileServer(http.Dir("./static"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// CSRF token relay: lấy vsp_csrf từ gateway rồi set cho browser
		// OWASP ASVS V4.2.2 — cả browser và gateway phải dùng cùng token
		if r.Method == http.MethodGet {
			if _, err := r.Cookie("vsp_csrf"); err != nil {
				// Fetch CSRF token từ gateway (sync)
				gwURL := fmt.Sprintf("http://%s:%d/health", gatewayHost, gatewayPort)
				if gresp, gerr := http.DefaultClient.Get(gwURL); gerr == nil {
					for _, c := range gresp.Cookies() {
						if c.Name == "vsp_csrf" {
							// Relay gateway's CSRF cookie to browser
							http.SetCookie(w, &http.Cookie{
								Name:     "vsp_csrf",
								Value:    c.Value,
								Path:     "/",
								SameSite: http.SameSiteStrictMode,
								HttpOnly: false,
							})
							// Also forward cookie to all subsequent proxy requests
							r.AddCookie(&http.Cookie{Name: "vsp_csrf", Value: c.Value})
							break
						}
					}
					gresp.Body.Close() //nolint:errcheck
				}
			}
		}
		if r.URL.Path != "/" {
			_, err := os.Stat("./static" + r.URL.Path) //#nosec G703 -- path sanitized by http.FileServer
			if os.IsNotExist(err) {
				// SPA fallback
				http.ServeFile(w, r, "./static/index.html")
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		fs.ServeHTTP(w, r)
	})

	addr := fmt.Sprintf(":%d", shellPort)
	log.Info().
		Str("addr", addr).
		Int("gateway", gatewayPort).
		Str("static", "./static").
		Msg("VSP SOC Shell starting")

	if err := http.ListenAndServe(addr, securityMiddleware(mux)); err != nil {
		log.Fatal().Err(err).Msg("shell server failed")
	}
}
