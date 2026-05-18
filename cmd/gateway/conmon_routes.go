package main

import (
	"net/http"

	"github.com/vsp/platform/internal/api/handler"
)

// registerConMonRoutes wires ConMon endpoints onto the gateway mux.
// Caller must pass the same db pointer used by the rest of the gateway,
// and an authentication middleware to wrap the handlers.
func registerConMonRoutes(mux *http.ServeMux, h *handler.ConMonHandler, withAuth func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/v1/conmon/schedules", withAuth(methodGuard([]string{"GET","POST"}, h.Schedules)))
	mux.HandleFunc("/api/v1/conmon/deviations", withAuth(methodGuard([]string{"GET"}, h.Deviations)))
	mux.HandleFunc("/api/v1/conmon/cadence", withAuth(methodGuard([]string{"GET"}, h.CadenceStatus)))

	// Acknowledgement uses a path with an embedded id:
	//   POST /api/v1/conmon/deviations/{id}/acknowledge
	mux.HandleFunc("/api/v1/conmon/deviations/", withAuth(func(w http.ResponseWriter, r *http.Request) {
		// Only handle the /acknowledge sub-path; otherwise 404
		if !endsWith(r.URL.Path, "/acknowledge") {
			http.NotFound(w, r)
			return
		}
		h.AckDeviation(w, r)
	}))
}

func methodGuard(allowed []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, m := range allowed {
			if r.Method == m {
				next(w, r)
				return
			}
		}
		w.Header().Set("Allow", allowed[0])
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func endsWith(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}
