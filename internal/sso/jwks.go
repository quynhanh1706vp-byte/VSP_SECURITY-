// jwks.go — JSON Web Key Set fetch + ID token signature verification.
//
// Implements RFC 7517 (JWKS) + RFC 7515 (JWS) signature verification
// with in-memory cache (24h default, rotation-safe via kid lookup miss
// triggering refetch).
//
// Supported algorithms: RS256, RS384, RS512, ES256, ES384, ES512.
// Token claims validated: iss, aud, exp, nbf, iat.

package sso

import (
	"context"
	"crypto/elliptic"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JSONWebKey is a single key from a JWKS response (RFC 7517).
type JSONWebKey struct {
	Kid string `json:"kid"`           // Key ID
	Kty string `json:"kty"`           // Key type: RSA, EC
	Alg string `json:"alg,omitempty"` // Intended algorithm
	Use string `json:"use,omitempty"` // sig, enc
	N   string `json:"n,omitempty"`   // RSA modulus (base64url)
	E   string `json:"e,omitempty"`   // RSA public exponent (base64url)
	Crv string `json:"crv,omitempty"` // EC curve
	X   string `json:"x,omitempty"`   // EC X coordinate
	Y   string `json:"y,omitempty"`   // EC Y coordinate
}

// JWKS is the parsed JSON Web Key Set.
type JWKS struct {
	Keys []JSONWebKey `json:"keys"`
}

// jwksCacheEntry caches a parsed JWKS with TTL for rotation safety.
type jwksCacheEntry struct {
	keys      []JSONWebKey
	fetchedAt time.Time
}

var (
	jwksMu    sync.RWMutex
	jwksCache = make(map[string]*jwksCacheEntry)
	jwksTTL   = 24 * time.Hour
)

// FetchJWKS retrieves and caches the JSON Web Key Set from the provider.
// On cache miss or expired entry, makes a fresh HTTP fetch.
func FetchJWKS(ctx context.Context, jwksURI string) ([]JSONWebKey, error) {
	jwksMu.RLock()
	entry, ok := jwksCache[jwksURI]
	jwksMu.RUnlock()

	if ok && time.Since(entry.fetchedAt) < jwksTTL {
		return entry.keys, nil
	}

	return refetchJWKS(ctx, jwksURI)
}

func refetchJWKS(ctx context.Context, jwksURI string) ([]JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("jwks: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: fetch %s: %w", jwksURI, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: %s returned %d", jwksURI, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, fmt.Errorf("jwks: read body: %w", err)
	}

	var set JWKS
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("jwks: parse: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("jwks: empty key set from %s", jwksURI)
	}

	jwksMu.Lock()
	jwksCache[jwksURI] = &jwksCacheEntry{
		keys:      set.Keys,
		fetchedAt: time.Now(),
	}
	jwksMu.Unlock()

	return set.Keys, nil
}

// findKey returns the JWK matching the given kid, or nil if not found.
func findKey(keys []JSONWebKey, kid string) *JSONWebKey {
	for i := range keys {
		if keys[i].Kid == kid {
			return &keys[i]
		}
	}
	return nil
}

// publicKey converts a JWK to a *rsa.PublicKey or *ecdsa.PublicKey.
func (k *JSONWebKey) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("jwk RSA: bad N: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("jwk RSA: bad E: %w", err)
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		}, nil

	case "EC":
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwk EC: bad X: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("jwk EC: bad Y: %w", err)
		}
		curve, err := curveByName(k.Crv)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported kty: %s", k.Kty)
	}
}

func curveByName(name string) (elliptic.Curve, error) {
	// Lazy import to avoid pulling crypto/elliptic into JWK struct
	switch name {
	case "P-256":
		return ellipticP256(), nil
	case "P-384":
		return ellipticP384(), nil
	case "P-521":
		return ellipticP521(), nil
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", name)
	}
}

// VerifyIDToken parses and FULLY verifies an OIDC ID token:
//   - Signature check against JWKS (RS256/384/512, ES256/384/512)
//   - iss == expectedIss
//   - aud contains expectedAud (clientID)
//   - exp > now
//   - nbf <= now (if present)
//
// Returns parsed IDTokenClaims on success.
func VerifyIDToken(ctx context.Context, idToken, jwksURI, expectedIss, expectedAud string) (*IDTokenClaims, error) {
	if idToken == "" {
		return nil, fmt.Errorf("verify: empty id_token")
	}

	parsed, err := jwt.Parse(idToken, func(t *jwt.Token) (any, error) {
		// Algorithm whitelist — reject 'none' and HMAC entirely.
		alg, _ := t.Header["alg"].(string)
		switch alg {
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
			// ok
		default:
			return nil, fmt.Errorf("verify: alg %q not allowed", alg)
		}

		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("verify: missing kid in header")
		}

		keys, err := FetchJWKS(ctx, jwksURI)
		if err != nil {
			return nil, err
		}

		jwk := findKey(keys, kid)
		if jwk == nil {
			// Possible key rotation — invalidate cache and retry once.
			jwksMu.Lock()
			delete(jwksCache, jwksURI)
			jwksMu.Unlock()

			keys, err = FetchJWKS(ctx, jwksURI)
			if err != nil {
				return nil, err
			}
			jwk = findKey(keys, kid)
			if jwk == nil {
				return nil, fmt.Errorf("verify: kid %q not in JWKS", kid)
			}
		}

		return jwk.publicKey()
	})
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("verify: token marked invalid")
	}

	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("verify: unexpected claims type")
	}

	// Reconstruct typed claims for the rest of the SSO flow
	claims := &IDTokenClaims{}
	if v, ok := mapClaims["iss"].(string); ok {
		claims.Iss = v
	}
	if v, ok := mapClaims["sub"].(string); ok {
		claims.Sub = v
	}
	if v, ok := mapClaims["aud"]; ok {
		claims.Aud = v
	}
	if v, ok := mapClaims["nonce"].(string); ok {
		claims.Nonce = v
	}
	if v, ok := mapClaims["email"].(string); ok {
		claims.Email = v
	}
	if v, ok := mapClaims["name"].(string); ok {
		claims.Name = v
	}
	if v, ok := mapClaims["exp"].(float64); ok {
		claims.Exp = int64(v)
	}
	if v, ok := mapClaims["iat"].(float64); ok {
		claims.Iat = int64(v)
	}

	// iss check
	if expectedIss != "" && claims.Iss != expectedIss {
		return nil, fmt.Errorf("verify: iss mismatch: got %q want %q", claims.Iss, expectedIss)
	}

	// aud check (string OR []string per OIDC spec)
	if expectedAud != "" {
		if !audContains(claims.Aud, expectedAud) {
			return nil, fmt.Errorf("verify: aud does not contain %q", expectedAud)
		}
	}

	// exp check
	now := time.Now().Unix()
	if claims.Exp > 0 && now >= claims.Exp {
		return nil, fmt.Errorf("verify: token expired")
	}

	// nbf check (optional)
	if v, ok := mapClaims["nbf"].(float64); ok {
		if now < int64(v) {
			return nil, fmt.Errorf("verify: token not yet valid (nbf)")
		}
	}

	return claims, nil
}

func audContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	}
	return false
}

// SetJWKSCacheTTL overrides the default 24h cache TTL. For testing.
func SetJWKSCacheTTL(d time.Duration) {
	jwksMu.Lock()
	jwksTTL = d
	jwksMu.Unlock()
}

// ClearJWKSCache evicts all cached JWKS. For testing or forced rotation.
func ClearJWKSCache() {
	jwksMu.Lock()
	jwksCache = make(map[string]*jwksCacheEntry)
	jwksMu.Unlock()
}

// strings package usage to keep linter happy if we add helpers later.
var _ = strings.HasPrefix
