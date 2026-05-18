package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendSlack_OK(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(Config{AllowPrivateIPs: true})
	err := n.Send(context.Background(), "slack", srv.URL, "hello world", "", map[string]interface{}{
		"channel": "#soc-alerts",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got["text"] != "hello world" {
		t.Errorf("want text=hello world, got %v", got["text"])
	}
	if got["channel"] != "#soc-alerts" {
		t.Errorf("want channel=#soc-alerts, got %v", got["channel"])
	}
}

func TestSendSlack_FallbackToDefault(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(Config{
		SlackDefaultWebhook: srv.URL,
		AllowPrivateIPs:     true,
	})
	// "to" is a channel name, not a URL — should fall back to default webhook.
	if err := n.Send(context.Background(), "slack", "#fallback", "msg", "", nil); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !hit {
		t.Fatal("default webhook not hit")
	}
}

func TestSendDiscord_OK(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := New(Config{AllowPrivateIPs: true})
	err := n.Send(context.Background(), "discord", srv.URL, "ping", "", map[string]interface{}{
		"username": "vsp-bot",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got["content"] != "ping" {
		t.Errorf("want content=ping, got %v", got["content"])
	}
	if got["username"] != "vsp-bot" {
		t.Errorf("want username=vsp-bot, got %v", got["username"])
	}
}

func TestSendTeams_OK(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(Config{AllowPrivateIPs: true})
	err := n.Send(context.Background(), "teams", srv.URL, "alert text", "", map[string]interface{}{
		"title": "Critical",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got["@type"] != "MessageCard" {
		t.Errorf("want @type=MessageCard, got %v", got["@type"])
	}
	if got["title"] != "Critical" {
		t.Errorf("want title=Critical, got %v", got["title"])
	}
}

func TestSendGeneric_OK(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(Config{AllowPrivateIPs: true})
	err := n.Send(context.Background(), "webhook", srv.URL, "hi", "", map[string]interface{}{
		"severity": "HIGH",
		"asset":    "api-gw-01",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got["message"] != "hi" {
		t.Errorf("want message=hi, got %v", got["message"])
	}
	if got["severity"] != "HIGH" {
		t.Errorf("want severity=HIGH, got %v", got["severity"])
	}
}

func TestSend_UnsupportedChannel(t *testing.T) {
	n := New(Config{AllowPrivateIPs: true})
	err := n.Send(context.Background(), "carrier-pigeon", "x", "y", "", nil)
	if err == nil {
		t.Fatal("want error for unsupported channel")
	}
	if !strings.Contains(err.Error(), "unsupported channel") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestSend_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := New(Config{AllowPrivateIPs: true})
	err := n.Send(context.Background(), "slack", srv.URL, "boom", "", nil)
	if err == nil {
		t.Fatal("want error on HTTP 500")
	}
	if !strings.Contains(err.Error(), "http 500") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestSend_NoURLNoDefault(t *testing.T) {
	n := New(Config{AllowPrivateIPs: true})
	err := n.Send(context.Background(), "slack", "#noconfig", "msg", "", nil)
	if err == nil {
		t.Fatal("want error when no URL and no default")
	}
	if !strings.Contains(err.Error(), "webhook URL required") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestSend_EmailNoOp(t *testing.T) {
	n := New(Config{AllowPrivateIPs: true})
	// Email is a no-op currently — should not error.
	if err := n.Send(context.Background(), "email", "soc@example.com", "msg", "", nil); err != nil {
		t.Errorf("email should be no-op, got: %v", err)
	}
}

func TestSSRFGuard_BlocksLoopback(t *testing.T) {
	// Production mode (AllowPrivateIPs=false): loopback rejected before HTTP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(Config{}) // AllowPrivateIPs = false
	err := n.Send(context.Background(), "slack", srv.URL, "msg", "", nil)
	if err == nil {
		t.Fatal("want SSRF guard to block loopback")
	}
	if !strings.Contains(err.Error(), "private/loopback") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestSSRFGuard_BlocksFileScheme(t *testing.T) {
	n := New(Config{})
	err := n.Send(context.Background(), "webhook", "file:///etc/passwd", "msg", "", nil)
	if err == nil {
		t.Fatal("want SSRF guard to block file://")
	}
	if !strings.Contains(err.Error(), "only http/https") {
		t.Errorf("wrong error: %v", err)
	}
}
