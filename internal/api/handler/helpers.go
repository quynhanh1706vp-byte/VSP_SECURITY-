package handler

import (
	"encoding/json"
	"net/http"
)

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ── Input validation helpers ──────────────────────────────────────────────────

// validateUUID kiểm tra string có phải UUID hợp lệ không.
func validateUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// validatePositiveInt kiểm tra string có phải số nguyên dương không.
func validatePositiveInt(s string, max int) (int, bool) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > max {
			return max, true
		}
	}
	if n <= 0 {
		return 0, false
	}
	return n, true
}

// sanitizeString giới hạn độ dài và strip control chars.
func sanitizeString(s string, maxLen int) string {
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

// validateRID returns true if s looks like a valid Run ID (alphanumeric + _ -).
func validateRID(s string) bool {
	if len(s) == 0 || len(s) > 100 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
