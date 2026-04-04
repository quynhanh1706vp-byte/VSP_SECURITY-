package versioning

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractVersion(t *testing.T) {
	cases := []struct {
		path    string
		want    string
	}{
		{"/api/v1/findings", "v1"},
		{"/api/v2/findings", "v2"},
		{"/api/v1/auth/login", "v1"},
		{"/health", "v1"},           // fallback to current
		{"/", "v1"},
		{"/api/v3/test", "v1"},      // unknown version → fallback
	}

	for _, c := range cases {
		got := extractVersion(c.path)
		if got != c.want {
			t.Errorf("extractVersion(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestMiddleware_InjectsVersion(t *testing.T) {
	var gotVersion string
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if gotVersion != "v1" {
		t.Errorf("expected v1, got %q", gotVersion)
	}
	if w.Header().Get("X-API-Version") != "v1" {
		t.Error("expected X-API-Version header")
	}
}

func TestFromContext_Default(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	v := FromContext(req.Context())
	if v != Current {
		t.Errorf("expected %q, got %q", Current, v)
	}
}

func TestDeprecatedV1_Headers(t *testing.T) {
	mw := DeprecatedV1("2026-12-31", "/api/v2/test")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Deprecation") != "true" {
		t.Error("expected Deprecation header")
	}
	if w.Header().Get("Sunset") != "2026-12-31" {
		t.Error("expected Sunset header")
	}
	if w.Header().Get("Link") == "" {
		t.Error("expected Link header with successor")
	}
}
