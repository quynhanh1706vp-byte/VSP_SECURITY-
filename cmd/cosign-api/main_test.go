package main

import (
	"errors"
	"testing"
)

// TestClassifyVerifyFailure pins the status taxonomy so future refactors
// can't silently revert to the old "every-failure-is-tampered" behaviour.
// Each case represents a real cosign output we have observed in
// staging or dev.
func TestClassifyVerifyFailure(t *testing.T) {
	cases := []struct {
		name     string
		combined string
		runErr   error
		want     string
	}{
		{
			name:     "success → verified",
			combined: "Verification for nginx:1.25 -- OK",
			runErr:   nil,
			want:     "verified",
		},
		{
			name:     "binary missing → unavailable (NOT tampered)",
			combined: `exec: "cosign": executable file not found in $PATH`,
			runErr:   errors.New("exit 127"),
			want:     "unavailable",
		},
		{
			name:     "no signatures → unsigned (NOT tampered)",
			combined: "Error: no signatures found for image",
			runErr:   errors.New("exit 1"),
			want:     "unsigned",
		},
		{
			name:     "image not in registry → not_found (NOT tampered)",
			combined: "GET https://localhost:5000/v2/vsp/alpine/manifests/3.19: MANIFEST_UNKNOWN",
			runErr:   errors.New("exit 1"),
			want:     "not_found",
		},
		{
			name:     "registry unreachable → not_found (NOT tampered)",
			combined: "dial tcp 10.0.0.5:5000: connect: connection refused",
			runErr:   errors.New("exit 1"),
			want:     "not_found",
		},
		{
			name:     "signature mismatch → tampered (the real security event)",
			combined: "Error: signature verification failed: not signed by configured key",
			runErr:   errors.New("exit 1"),
			want:     "tampered",
		},
		{
			name:     "unknown failure → failed (refuse to cry wolf)",
			combined: "some weird error we have not seen before",
			runErr:   errors.New("exit 99"),
			want:     "failed",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := classifyVerifyFailure(c.combined, c.runErr)
			if got != c.want {
				t.Fatalf("classifyVerifyFailure(%q): got %q, want %q",
					c.combined, got, c.want)
			}
		})
	}
}
