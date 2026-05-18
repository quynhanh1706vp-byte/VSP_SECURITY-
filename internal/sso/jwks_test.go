package sso

import (
	"testing"
	"time"
)

func TestAudContains(t *testing.T) {
	cases := []struct {
		name string
		aud  any
		want string
		ok   bool
	}{
		{"string match", "client-123", "client-123", true},
		{"string mismatch", "other", "client-123", false},
		{"slice match", []any{"client-123", "other"}, "client-123", true},
		{"slice mismatch", []any{"a", "b"}, "client-123", false},
		{"typed slice", []string{"client-123"}, "client-123", true},
		{"empty", nil, "client-123", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := audContains(c.aud, c.want)
			if got != c.ok {
				t.Errorf("audContains(%v, %q) = %v, want %v", c.aud, c.want, got, c.ok)
			}
		})
	}
}

func TestSetJWKSCacheTTL(t *testing.T) {
	defer SetJWKSCacheTTL(24 * time.Hour) // restore
	SetJWKSCacheTTL(1 * time.Second)
	if jwksTTL != 1*time.Second {
		t.Errorf("TTL not updated")
	}
}

func TestClearJWKSCache(t *testing.T) {
	ClearJWKSCache()
	if len(jwksCache) != 0 {
		t.Errorf("cache not cleared")
	}
}

func TestFindKey(t *testing.T) {
	keys := []JSONWebKey{
		{Kid: "abc", Kty: "RSA"},
		{Kid: "xyz", Kty: "RSA"},
	}
	if k := findKey(keys, "xyz"); k == nil || k.Kid != "xyz" {
		t.Errorf("findKey miss")
	}
	if k := findKey(keys, "missing"); k != nil {
		t.Errorf("findKey false positive")
	}
}
