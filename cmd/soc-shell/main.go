package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

func main() {
	viper.SetDefault("server.shell_port", 8922)
	viper.SetDefault("server.gateway_port", 8921)
	viper.SetDefault("log.level", "info")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	viper.ReadInConfig()

	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	shellPort   := viper.GetInt("server.shell_port")
	gatewayPort := viper.GetInt("server.gateway_port")
	gatewayURL, _ := url.Parse(fmt.Sprintf("http://localhost:%d", gatewayPort))
	proxy := httputil.NewSingleHostReverseProxy(gatewayURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"soc-shell","port":%d}`, shellPort)
	})
	// Serve static files, fallback to index.html for SPA
	fs := http.FileServer(http.Dir("./static"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			_, err := os.Stat("./static" + r.URL.Path)
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

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal().Err(err).Msg("shell server failed")
	}
}
