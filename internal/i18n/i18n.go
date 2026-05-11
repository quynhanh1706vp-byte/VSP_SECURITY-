// Package i18n provides per-request localisation for VSP.
//
// Locale selection precedence (highest first):
//  1. ?lang= query parameter (vi, en) — useful for testing & shareable URLs
//  2. X-VSP-Locale request header — what authenticated SPA clients send
//  3. user_settings.locale row in DB (set via /api/v1/locale endpoint)
//  4. Accept-Language header — RFC 4647 quality-weighted negotiation
//  5. defaultLocale (currently "vi") — VSP's primary market is Vietnam
//
// We deliberately choose Vietnamese as default rather than English: the
// platform is Vietnamese-first per project naming, and English-only ops
// teams can opt into "en" via header / user setting.
//
// Translation lookup is a flat key→string map per locale. Missing keys
// fall back to default locale, then to the key itself (so the call site
// is debuggable).
package i18n

import (
	"context"
	"net/http"
	"strings"
	"sync"
)

const (
	defaultLocale = "vi"
	headerLocale  = "X-VSP-Locale"
)

// Supported is the set of locales the catalogue knows. Adding a new
// locale = drop a translation map below and append here.
var Supported = []string{"vi", "en"}

// catalogue is the in-memory translation store. Keyed by locale, each
// inner map keys by stable identifier (e.g. "auth.invalid_credentials").
//
// Keep keys hierarchical (dot-separated) so future translation tooling
// (Crowdin, POEditor) can group them.
var catalogue = map[string]map[string]string{
	"vi": {
		// Auth
		"auth.invalid_credentials": "Email hoặc mật khẩu không đúng.",
		"auth.unauthorized":        "Bạn cần đăng nhập để truy cập tài nguyên này.",
		"auth.forbidden":           "Bạn không có quyền truy cập tài nguyên này.",
		"auth.password_too_short":  "Mật khẩu phải có ít nhất 12 ký tự.",
		"auth.password_breached":   "Mật khẩu này đã xuất hiện trong các vụ rò rỉ — vui lòng chọn mật khẩu khác.",
		"auth.password_reused":     "Mật khẩu này đã được sử dụng gần đây — vui lòng chọn mật khẩu khác.",
		"auth.mfa_required":        "Cần mã xác thực hai yếu tố (MFA).",
		"auth.mfa_invalid":         "Mã MFA không hợp lệ.",
		"auth.account_locked":      "Tài khoản bị khoá tạm thời do quá nhiều lần đăng nhập sai.",
		// Tenant / data
		"tenant.not_found":    "Không tìm thấy tổ chức.",
		"resource.not_found":  "Không tìm thấy tài nguyên.",
		"validation.required": "Trường này là bắt buộc.",
		"validation.too_long": "Giá trị quá dài.",
		// PRO gating
		"pro.required": "Tính năng này yêu cầu gói PRO.",
		// Compliance
		"compliance.evidence_uploaded": "Đã tải lên bằng chứng tuân thủ.",
		"compliance.erasure_scheduled": "Yêu cầu xoá dữ liệu đã được ghi nhận. Dữ liệu sẽ bị xoá sau 30 ngày.",
		"compliance.export_ready":      "Bản xuất dữ liệu của bạn đã sẵn sàng.",
		// Generic
		"error.internal":     "Lỗi hệ thống. Vui lòng thử lại sau.",
		"error.rate_limited": "Quá nhiều yêu cầu. Vui lòng đợi và thử lại.",
		"ok":                 "Thành công.",
	},
	"en": {
		"auth.invalid_credentials":     "Invalid email or password.",
		"auth.unauthorized":            "You must be authenticated to access this resource.",
		"auth.forbidden":               "You do not have permission to access this resource.",
		"auth.password_too_short":      "Password must be at least 12 characters.",
		"auth.password_breached":       "This password appears in known breaches — please choose a different one.",
		"auth.password_reused":         "This password was recently used — please choose a different one.",
		"auth.mfa_required":            "Multi-factor authentication code is required.",
		"auth.mfa_invalid":             "Invalid MFA code.",
		"auth.account_locked":          "Account is temporarily locked due to too many failed login attempts.",
		"tenant.not_found":             "Tenant not found.",
		"resource.not_found":           "Resource not found.",
		"validation.required":          "This field is required.",
		"validation.too_long":          "Value is too long.",
		"pro.required":                 "This feature requires the PRO plan.",
		"compliance.evidence_uploaded": "Compliance evidence uploaded.",
		"compliance.erasure_scheduled": "Erasure request recorded. Data will be deleted after 30 days.",
		"compliance.export_ready":      "Your data export is ready.",
		"error.internal":               "Internal error. Please try again later.",
		"error.rate_limited":           "Too many requests. Please wait and retry.",
		"ok":                           "OK.",
	},
}

var catMu sync.RWMutex

// localeKey is the context key for the per-request locale. Unexported so
// callers go through Locale() / WithLocale().
type localeKey struct{}

// Locale returns the locale stored on the context, or defaultLocale.
func Locale(ctx context.Context) string {
	if v, ok := ctx.Value(localeKey{}).(string); ok && v != "" {
		return v
	}
	return defaultLocale
}

// WithLocale returns a new context carrying the locale.
func WithLocale(ctx context.Context, loc string) context.Context {
	return context.WithValue(ctx, localeKey{}, normalize(loc))
}

// T translates a key using the locale on the context. If the key is
// missing in the requested locale, falls back to default; if missing
// there too, returns the key itself (visible-bug-friendly).
func T(ctx context.Context, key string) string {
	return TLoc(Locale(ctx), key)
}

// TLoc translates without a context — useful for background workers.
func TLoc(loc, key string) string {
	loc = normalize(loc)
	catMu.RLock()
	defer catMu.RUnlock()
	if m, ok := catalogue[loc]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if loc != defaultLocale {
		if m, ok := catalogue[defaultLocale]; ok {
			if v, ok := m[key]; ok {
				return v
			}
		}
	}
	return key
}

// Middleware extracts the locale from the request and stores it on the
// context. Order matches the package-level precedence.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loc := pickLocale(r)
		// Surface the resolved locale to clients (for cache-keying / SPA UX).
		w.Header().Set("Content-Language", loc)
		next.ServeHTTP(w, r.WithContext(WithLocale(r.Context(), loc)))
	})
}

func pickLocale(r *http.Request) string {
	// 1. ?lang=
	if q := strings.TrimSpace(r.URL.Query().Get("lang")); q != "" {
		if isSupported(q) {
			return normalize(q)
		}
	}
	// 2. X-VSP-Locale
	if h := strings.TrimSpace(r.Header.Get(headerLocale)); h != "" {
		if isSupported(h) {
			return normalize(h)
		}
	}
	// 3. user setting — looked up by callers that have DB access; we only
	//    handle 1, 2, 4, 5 here. Handlers can call WithLocale themselves
	//    after consulting user_settings.
	// 4. Accept-Language
	if al := r.Header.Get("Accept-Language"); al != "" {
		if loc := negotiateAcceptLanguage(al); loc != "" {
			return loc
		}
	}
	// 5. default
	return defaultLocale
}

// negotiateAcceptLanguage walks an Accept-Language header (RFC 4647) and
// returns the highest-quality locale we support. Quality weights (q=...)
// are honoured; unsupported tags are skipped.
func negotiateAcceptLanguage(header string) string {
	type tagQ struct {
		tag string
		q   float64
	}
	var candidates []tagQ
	for _, part := range strings.Split(header, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		tag := p
		q := 1.0
		if semi := strings.Index(p, ";"); semi >= 0 {
			tag = strings.TrimSpace(p[:semi])
			rest := p[semi+1:]
			if eq := strings.Index(rest, "q="); eq >= 0 {
				// best effort; ignore parse failure
				_, _ = parseQ(rest[eq+2:], &q)
			}
		}
		candidates = append(candidates, tagQ{tag: tag, q: q})
	}
	// Pick highest q that maps to a supported locale. Simple two-letter
	// match; we don't do region fallbacks (vi-VN → vi) explicitly, but
	// the prefix check below covers it.
	best := ""
	bestQ := -1.0
	for _, c := range candidates {
		base := strings.ToLower(c.tag)
		if dash := strings.IndexByte(base, '-'); dash > 0 {
			base = base[:dash]
		}
		if isSupported(base) && c.q > bestQ {
			best = base
			bestQ = c.q
		}
	}
	return best
}

func parseQ(s string, out *float64) (int, error) {
	// We hand-roll this rather than pull strconv.ParseFloat into the
	// hot path; q values are always 0.0 – 1.0 with limited precision.
	// Read up to 5 chars (e.g. "0.875").
	end := len(s)
	if end > 5 {
		end = 5
	}
	for i := 0; i < end; i++ {
		c := s[i]
		if (c < '0' || c > '9') && c != '.' {
			end = i
			break
		}
	}
	if end == 0 {
		return 0, nil
	}
	// Cheap parse without strconv — we only need 1 decimal-point accuracy.
	whole, frac := 0, 0
	fracDiv := 1
	dot := false
	for i := 0; i < end; i++ {
		c := s[i]
		if c == '.' {
			dot = true
			continue
		}
		if !dot {
			whole = whole*10 + int(c-'0')
		} else {
			frac = frac*10 + int(c-'0')
			fracDiv *= 10
		}
	}
	*out = float64(whole) + float64(frac)/float64(fracDiv)
	return end, nil
}

func normalize(loc string) string {
	loc = strings.ToLower(strings.TrimSpace(loc))
	if dash := strings.IndexByte(loc, '-'); dash > 0 {
		loc = loc[:dash]
	}
	if !isSupported(loc) {
		return defaultLocale
	}
	return loc
}

func isSupported(loc string) bool {
	loc = strings.ToLower(loc)
	if dash := strings.IndexByte(loc, '-'); dash > 0 {
		loc = loc[:dash]
	}
	for _, s := range Supported {
		if s == loc {
			return true
		}
	}
	return false
}
