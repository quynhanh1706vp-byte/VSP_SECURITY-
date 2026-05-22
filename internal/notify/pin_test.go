package notify

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// spkiPinFromTLS returns the base64-SHA-256 of the TLS server's leaf
// SubjectPublicKeyInfo, which is the wire format we store.
func spkiPinFromTLS(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	cert, err := x509.ParseCertificate(ts.Certificate().Raw)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func TestPinningTransport_PinMatch(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer ts.Close()
	pin := spkiPinFromTLS(t, ts)

	pins := NewPinSet()
	host := ts.Listener.Addr().String()
	// Strip port for the pin map (PinSet keys by hostname).
	hostname := stripPort(host)
	pins.Set(hostname, []string{pin})

	tr := NewPinningTransport(pins)
	// httptest.NewTLSServer uses self-signed cert — bypass the system root
	// pool but keep the pinning callback live.
	tr.Base.TLSClientConfig.RootCAs = x509Pool(t, ts)

	c := &http.Client{Transport: tr}
	resp, err := c.Get(ts.URL)
	if err != nil {
		t.Fatalf("matching pin should succeed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestPinningTransport_PinMismatch(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer ts.Close()

	pins := NewPinSet()
	hostname := stripPort(ts.Listener.Addr().String())
	pins.Set(hostname, []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}) // wrong pin

	tr := NewPinningTransport(pins)
	tr.Base.TLSClientConfig.RootCAs = x509Pool(t, ts)
	c := &http.Client{Transport: tr}

	_, err := c.Get(ts.URL)
	if err == nil {
		t.Fatal("mismatched pin should fail")
	}
}

func TestPinningTransport_NoPinIsAllowed(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()
	// PinSet has no entry for this host — should pass.
	pins := NewPinSet()
	tr := NewPinningTransport(pins)
	tr.Base.TLSClientConfig.RootCAs = x509Pool(t, ts)
	c := &http.Client{Transport: tr}

	resp, err := c.Get(ts.URL)
	if err != nil {
		t.Fatalf("no pin → no enforcement, got error %v", err)
	}
	resp.Body.Close()
}

func stripPort(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

func x509Pool(t *testing.T, ts *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return pool
}

// Compile-time check that PinningTransport implements RoundTripper.
var _ http.RoundTripper = (*PinningTransport)(nil)
var _ tls.ConnectionState // keep imports honest
