// Package auth — HIBP (haveibeenpwned.com) breached-password check.
//
// Uses the Pwned Passwords k-anonymity API: we send only the first 5 hex
// chars of the SHA-1 password hash, the API returns all suffixes seen in
// breaches with their occurrence count. We never send the password or its
// full hash. This is the pattern endorsed by NIST SP 800-63B-3 §5.1.1.2.
//
// The check is best-effort: if HIBP is unreachable we DO NOT block the
// password change (availability > paranoia). Operators who want strict
// enforcement should set VSP_HIBP_REQUIRED=1 — then a network failure
// returns ErrHIBPUnavailable and the caller can decide.
//
// Threshold: any non-zero count rejects the password. NIST does not
// specify a threshold; we err on the strict side because a single breach
// hit means the password is in attacker wordlists.
package auth

import (
	"bufio"
	"context"
	"crypto/sha1" //#nosec G505 — HIBP API mandates SHA-1 (k-anonymity prefix only)
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrPasswordBreached is returned when the password appears in HIBP.
var ErrPasswordBreached = errors.New("password appears in known breach corpus")

// ErrHIBPUnavailable is returned when HIBP is unreachable AND the operator
// has set VSP_HIBP_REQUIRED=1 (strict mode).
var ErrHIBPUnavailable = errors.New("HIBP service unavailable")

var hibpClient = &http.Client{Timeout: 5 * time.Second}

// CheckPasswordBreached returns ErrPasswordBreached if the password is in
// HIBP's corpus, nil if not. In permissive mode (default), network errors
// return nil — never block a password change because the breach service is
// down. In strict mode (VSP_HIBP_REQUIRED=1), network errors return
// ErrHIBPUnavailable.
func CheckPasswordBreached(ctx context.Context, password string) error {
	if password == "" {
		return nil
	}
	sum := sha1.Sum([]byte(password)) //#nosec G401 — k-anonymity prefix; HIBP API requirement
	hashHex := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix := hashHex[:5]
	suffix := hashHex[5:]

	url := "https://api.pwnedpasswords.com/range/" + prefix
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return strictOrNil(fmt.Errorf("hibp: build request: %w", err))
	}
	// Add-Padding asks HIBP to pad the response so observers can't infer
	// hit count from response size.
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "vsp-platform/1.x")

	resp, err := hibpClient.Do(req)
	if err != nil {
		return strictOrNil(fmt.Errorf("hibp: request: %w", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return strictOrNil(fmt.Errorf("hibp: HTTP %d", resp.StatusCode))
	}

	count, err := scanForSuffix(resp.Body, suffix)
	if err != nil {
		return strictOrNil(fmt.Errorf("hibp: parse: %w", err))
	}
	if count > 0 {
		return ErrPasswordBreached
	}
	return nil
}

// scanForSuffix walks the response (HASH_SUFFIX:COUNT lines) and returns
// the count for our suffix, or 0 if not present.
func scanForSuffix(r io.Reader, suffix string) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 256*1024)
	for sc.Scan() {
		line := sc.Text()
		// Lines look like "0018A45C4D1DEF81644B54AB7F969B88D65:1" — uppercase
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		if line[:colon] == suffix {
			n, err := strconv.Atoi(strings.TrimSpace(line[colon+1:]))
			if err != nil {
				return 0, err
			}
			return n, nil
		}
	}
	return 0, sc.Err()
}

func strictOrNil(err error) error {
	if os.Getenv("VSP_HIBP_REQUIRED") == "1" {
		return ErrHIBPUnavailable
	}
	return nil
}
