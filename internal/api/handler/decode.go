package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const maxBodyBytes = 1 << 20 // 1 MB hard cap

// decodeJSON đọc và validate request body:
// - Hard limit 1MB
// - DisallowUnknownFields (reject extra fields)
// - Trả về 400 với message rõ ràng
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var syntaxErr *json.SyntaxError
		var unmarshalErr *json.UnmarshalTypeError
		var maxBytesErr *http.MaxBytesError

		switch {
		case errors.As(err, &syntaxErr):
			jsonError(w, fmt.Sprintf("malformed JSON at position %d", syntaxErr.Offset),
				http.StatusBadRequest)
		case errors.As(err, &unmarshalErr):
			jsonError(w, fmt.Sprintf("invalid type for field %q: expected %s",
				unmarshalErr.Field, unmarshalErr.Type), http.StatusBadRequest)
		case errors.As(err, &maxBytesErr):
			jsonError(w, "request body too large (max 1MB)", http.StatusRequestEntityTooLarge)
		case errors.Is(err, io.EOF):
			jsonError(w, "request body must not be empty", http.StatusBadRequest)
		case errors.Is(err, io.ErrUnexpectedEOF):
			jsonError(w, "malformed JSON: unexpected end of input", http.StatusBadRequest)
		default:
			// Unknown field từ DisallowUnknownFields
			jsonError(w, fmt.Sprintf("invalid request: %s", err.Error()),
				http.StatusBadRequest)
		}
		return false
	}

	// Đảm bảo không còn data thừa sau JSON object
	if dec.More() {
		jsonError(w, "request body must contain only one JSON object",
			http.StatusBadRequest)
		return false
	}
	return true
}
