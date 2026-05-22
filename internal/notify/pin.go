// Package notify — outbound webhook certificate pinning (SPKI-SHA256).
//
// Customers in regulated verticals (banking, defense) ask: "what stops a
// compromised CA / DNS hijack from intercepting our webhook?" Plain TLS
// trusts the system root pool. Public-key pinning narrows that trust to a
// specific public key (or a small list) the tenant has registered.
//
// Pin format: base64 of SHA-256 over the leaf cert's
// SubjectPublicKeyInfo (matches the HPKP / RFC 7469 wire format and what
// `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`
// produces). Multiple pins are allowed (primary + backup) so rotations
// don't lock customers out — same pattern Chrome enforced for HPKP.
//
// Storage: per-tenant per-host map loaded at fanout start, refreshed on
// drainOnce ticks. A miss (no pin configured) → no pinning enforced; this
// preserves backwards compatibility for tenants that haven't opted in.
package notify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PinSet is a per-host set of acceptable SPKI hashes. A request whose
// peer cert chain doesn't carry any one of these pins is rejected with
// ErrCertPinMismatch.
type PinSet struct {
	mu   sync.RWMutex
	pins map[string]map[string]struct{} // host → set of base64 SPKI sha256
}

// ErrCertPinMismatch is returned when a webhook's TLS chain does not match
// any registered pin for the host.
var ErrCertPinMismatch = errors.New("certificate pin mismatch")

func NewPinSet() *PinSet {
	return &PinSet{pins: map[string]map[string]struct{}{}}
}

// Set replaces the pin set for one host. Empty pins clears pinning for
// that host. Hostnames are case-insensitive.
func (p *PinSet) Set(host string, pinsB64 []string) {
	host = strings.ToLower(strings.TrimSpace(host))
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(pinsB64) == 0 {
		delete(p.pins, host)
		return
	}
	set := make(map[string]struct{}, len(pinsB64))
	for _, p := range pinsB64 {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		set[p] = struct{}{}
	}
	p.pins[host] = set
}

// Has returns true when the host has at least one pin registered.
func (p *PinSet) Has(host string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.pins[strings.ToLower(host)]
	return ok
}

// Verify checks the cert chain returned by a TLS handshake against the
// registered pins for the host. Returns nil if no pins are registered for
// the host (no-op pinning), nil if any cert in the chain matches, or
// ErrCertPinMismatch otherwise.
func (p *PinSet) Verify(host string, chain []*x509.Certificate) error {
	p.mu.RLock()
	pinSet, ok := p.pins[strings.ToLower(host)]
	p.mu.RUnlock()
	if !ok || len(pinSet) == 0 {
		return nil
	}
	for _, cert := range chain {
		hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if _, hit := pinSet[base64.StdEncoding.EncodeToString(hash[:])]; hit {
			return nil
		}
	}
	return fmt.Errorf("%w: host %s, %d cert(s) seen, none matched", ErrCertPinMismatch, host, len(chain))
}

// PinningTransport wraps an http.Transport with per-request pin
// enforcement. We override DialTLSContext so we always have the dialed
// host (parsed from the connection's address) regardless of whether the
// client used SNI — this keeps pinning correct even for IP-literal
// targets, where SNI isn't sent.
type PinningTransport struct {
	Pins *PinSet
	Base *http.Transport
}

// NewPinningTransport returns a transport that enforces pinning via the
// supplied set. We do NOT disable hostname verification — pinning is
// layered on top of standard PKI, both must succeed.
func NewPinningTransport(pins *PinSet) *PinningTransport {
	pt := &PinningTransport{Pins: pins}
	pt.Base = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	pt.Base.DialTLSContext = pt.dialTLS
	return pt
}

// dialTLS replaces the default TLS dial. It performs the handshake
// against the standard CA chain, then runs the pin check against the
// resolved host (from the connection address). On pin mismatch the
// connection is closed before HTTP traffic flows.
func (t *PinningTransport) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	cfg := t.Base.TLSClientConfig.Clone()
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	if err := t.Pins.Verify(host, tlsConn.ConnectionState().PeerCertificates); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// RoundTrip delegates to the base transport. Pin check fires during dial.
func (t *PinningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.Base.RoundTrip(req)
}
