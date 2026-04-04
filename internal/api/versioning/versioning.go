package versioning

import (
	"context"
	"net/http"
	"strings"
)

const (
	V1      = "v1"
	V2      = "v2"
	Current = V1
)

type versionKey struct{}

func FromContext(ctx context.Context) string {
	v, _ := ctx.Value(versionKey{}).(string)
	if v == "" {
		return Current
	}
	return v
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version := extractVersion(r.URL.Path)
		ctx := context.WithValue(r.Context(), versionKey{}, version)
		w.Header().Set("X-API-Version", version)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractVersion(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "api" {
		switch parts[1] {
		case "v1", "v2":
			return parts[1]
		}
	}
	return Current
}

func DeprecatedV1(sunsetDate, successor string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Deprecation", "true")
			w.Header().Set("Sunset", sunsetDate)
			if successor != "" {
				w.Header().Set("Link", `<`+successor+`>; rel="successor-version"`)
			}
			next.ServeHTTP(w, r)
		})
	}
}
