package middleware

import (
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := chimw.GetReqID(r.Context())
		logger := log.With().
			Str("req_id", reqID).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("ip", r.RemoteAddr).
			Logger()
		ctx := logger.WithContext(r.Context())
		ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		defer func() {
			elapsed := time.Since(start)
			status := ww.Status()
			if status == 0 {
				status = 200
			}
			var event *zerolog.Event
			switch {
			case status >= 500:
				event = logger.Error()
			case status >= 400:
				event = logger.Warn()
			default:
				event = logger.Info()
			}
			event.Int("status", status).
				Int("bytes", ww.BytesWritten()).
				Dur("latency_ms", elapsed).
				Msg("http")
		}()
		next.ServeHTTP(ww, r.WithContext(ctx))
	})
}

func LoggerFromRequest(r *http.Request) zerolog.Logger {
	return zerolog.Ctx(r.Context()).With().Logger()
}
