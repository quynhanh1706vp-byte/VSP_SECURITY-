package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJsonOK(t *testing.T) {
	w := httptest.NewRecorder()
	jsonOK(w, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("expected value, got %q", result["key"])
	}
}

func TestJsonError(t *testing.T) {
	cases := []struct {
		msg  string
		code int
	}{
		{"unauthorized", http.StatusUnauthorized},
		{"not found", http.StatusNotFound},
		{"internal error", http.StatusInternalServerError},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		jsonError(w, c.msg, c.code)
		if w.Code != c.code {
			t.Errorf("msg=%q: expected %d, got %d", c.msg, c.code, w.Code)
		}
		var result map[string]string
		json.NewDecoder(w.Body).Decode(&result)
		if result["error"] != c.msg {
			t.Errorf("expected error=%q, got %q", c.msg, result["error"])
		}
	}
}

func TestDerefStr(t *testing.T) {
	s := "hello"
	if derefStr(&s) != "hello" {
		t.Error("expected hello")
	}
	if derefStr(nil) != "" {
		t.Error("expected empty string for nil")
	}
}
