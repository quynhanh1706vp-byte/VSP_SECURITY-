package auth

import (
	"net/http"
	"testing"
)

// FuzzParseJWT — feeds malformed JWT strings to parseJWT and asserts
// the function never panics. Returning an error is fine; crashing
// the gateway is not. Run with `go test -fuzz=FuzzParseJWT -fuzztime=30s`.
func FuzzParseJWT(f *testing.F) {
	// Seed corpus — known-shape inputs the fuzzer mutates.
	f.Add("")
	f.Add("not-a-jwt")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJIUzI1NiJ9..signature")
	f.Add("....")
	f.Add("\x00\x00\x00")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.")

	f.Fuzz(func(t *testing.T, token string) {
		// We don't care about the result — only that no panic occurs.
		// Defer/recover safety net so a panic is reported as test failure
		// rather than crashing the test process (which would kill other
		// fuzz inputs from the same run).
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseJWT panicked on input %q: %v", token, r)
			}
		}()
		_, _ = parseJWT(token, "fuzz-secret")
	})
}

// FuzzClientIP — RemoteAddr can be nearly anything (Go HTTP server
// usually sets it to "host:port", but a custom listener could feed
// arbitrary strings). Function must never panic.
func FuzzClientIP(f *testing.F) {
	f.Add("")
	f.Add("1.2.3.4")
	f.Add("1.2.3.4:5678")
	f.Add("[::1]:8080")
	f.Add("[invalid")
	f.Add("\x00")
	f.Add("a:b:c:d:e:f:g:h")

	f.Fuzz(func(t *testing.T, addr string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ClientIP panicked on RemoteAddr=%q: %v", addr, r)
			}
		}()
		req := &http.Request{RemoteAddr: addr}
		_ = ClientIP(req)
	})
}
