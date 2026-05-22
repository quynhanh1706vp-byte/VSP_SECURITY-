package telemetry

import (
	"crypto/rand"
	"encoding/hex"
)

// genTraceID returns a 32-character lowercase hex string (16 random bytes),
// matching the W3C Trace Context trace-id format.
func genTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("telemetry: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// genSpanID returns a 16-character lowercase hex string (8 random bytes),
// matching the W3C Trace Context span-id format.
func genSpanID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("telemetry: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
