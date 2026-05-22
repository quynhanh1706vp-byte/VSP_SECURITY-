package apisec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckSecurityHeaders_AllMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New(srv.URL)
	f := s.checkSecurityHeaders(context.Background(), "/")
	if f == nil {
		t.Fatal("expected finding for missing headers")
	}
	if f.Category != API08 {
		t.Errorf("expected API08, got %s", f.Category)
	}
}

func TestCheckInventory_Deprecated(t *testing.T) {
	s := New("http://example.com")
	f := s.checkInventory(context.Background(), "/api/v0/users")
	if f == nil {
		t.Fatal("expected finding for /api/v0/")
	}
}

func TestCheckInventory_Modern(t *testing.T) {
	s := New("http://example.com")
	f := s.checkInventory(context.Background(), "/api/v1/users")
	if f != nil {
		t.Error("expected no finding for /api/v1/")
	}
}
