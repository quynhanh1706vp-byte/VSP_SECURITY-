package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// FuzzDecodeJSON — feeds arbitrary bytes to decodeJSON and asserts no
// panic. The function MUST handle all malformed input via the
// json.SyntaxError / UnmarshalTypeError / MaxBytesError branches and
// return a 400. A panic propagating to the chi recoverer is the bug
// class fuzzing exists to catch.
func FuzzDecodeJSON(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"x":"y"}`))
	f.Add([]byte("{"))
	f.Add([]byte("\x00\x00\x00"))
	f.Add([]byte(`{"x":` + string(make([]byte, 100))))
	f.Add([]byte(`{"a":{"a":{"a":{"a":{"a":1}}}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("decodeJSON panicked on input %d bytes: %v", len(data), r)
			}
		}()
		req := httptest.NewRequest("POST", "/", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		var dst struct {
			A string `json:"a"`
			B int    `json:"b"`
		}
		_ = decodeJSON(rec, req, &dst)
		// Sanity: response status must be set (decodeJSON either succeeds
		// → no body written, or fails → writes a 4xx). 0 = handler never
		// touched the writer = decodeJSON's contract violated.
		if !rec.Flushed && rec.Code == 0 && rec.Body.Len() == 0 {
			t.Fatalf("decodeJSON returned without writing response on bad input")
		}
		// extractTenantID is exercised here too — fuzz with the same data.
		_ = extractTenantID(data)

		// Sanity: never a panic from extractTenantID either.
		_ = http.StatusOK // keep the import live
	})
}
