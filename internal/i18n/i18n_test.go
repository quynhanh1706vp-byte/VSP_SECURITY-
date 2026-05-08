package i18n

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestT_Lookup(t *testing.T) {
	ctx := WithLocale(context.Background(), "vi")
	if got := T(ctx, "auth.unauthorized"); got != "Bạn cần đăng nhập để truy cập tài nguyên này." {
		t.Fatalf("vi lookup: %q", got)
	}
	ctx = WithLocale(context.Background(), "en")
	if got := T(ctx, "auth.unauthorized"); got != "You must be authenticated to access this resource." {
		t.Fatalf("en lookup: %q", got)
	}
}

func TestT_FallbackToDefault(t *testing.T) {
	// Add a key only in vi, look up in en — should fall back to vi.
	catalogue["vi"]["test.only_vi"] = "chỉ vi"
	ctx := WithLocale(context.Background(), "en")
	if got := T(ctx, "test.only_vi"); got != "chỉ vi" {
		t.Fatalf("expected vi fallback, got %q", got)
	}
}

func TestT_FallbackToKey(t *testing.T) {
	if got := T(context.Background(), "nonexistent.key"); got != "nonexistent.key" {
		t.Fatalf("missing key should return key itself, got %q", got)
	}
}

func TestMiddleware_Precedence(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(*http.Request)
		expect string
	}{
		{"default", func(r *http.Request) {}, "vi"},
		{"accept-language en", func(r *http.Request) { r.Header.Set("Accept-Language", "en-US,en;q=0.8") }, "en"},
		{"accept-language vi-VN", func(r *http.Request) { r.Header.Set("Accept-Language", "vi-VN,vi;q=0.9") }, "vi"},
		{"X-VSP-Locale en overrides accept-language vi", func(r *http.Request) {
			r.Header.Set("Accept-Language", "vi")
			r.Header.Set("X-VSP-Locale", "en")
		}, "en"},
		{"?lang=en wins all", func(r *http.Request) {
			r.URL.RawQuery = "lang=en"
			r.Header.Set("X-VSP-Locale", "vi")
		}, "en"},
		{"unsupported locale falls back to default", func(r *http.Request) {
			r.Header.Set("X-VSP-Locale", "fr")
		}, "vi"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/x", nil)
			c.setup(r)
			w := httptest.NewRecorder()
			var got string
			Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = Locale(r.Context())
			})).ServeHTTP(w, r)
			if got != c.expect {
				t.Fatalf("expected %s, got %s", c.expect, got)
			}
			if cl := w.Header().Get("Content-Language"); cl != c.expect {
				t.Fatalf("Content-Language: expected %s, got %s", c.expect, cl)
			}
		})
	}
}

func TestNegotiate_QualityWeight(t *testing.T) {
	// English explicitly preferred over Vietnamese via q-weight.
	if got := negotiateAcceptLanguage("vi;q=0.3, en;q=0.9"); got != "en" {
		t.Fatalf("q-weighted: expected en, got %s", got)
	}
}
