package container

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type API struct {
	scanner *Scanner
}

func NewAPI(scanner *Scanner) *API {
	return &API{scanner: scanner}
}

// RegisterRoutes wires the container API under a NEW chi router group.
// Pass any middleware (auth, PRO gating, etc.) in mws — they are applied
// to this isolated group, leaving the rest of the parent router untouched.
//
// Calling with no middleware preserves the legacy "fully public" behaviour
// used by dev-stub and earlier builds.
func (a *API) RegisterRoutes(r chi.Router, mws ...func(http.Handler) http.Handler) {
	r.Group(func(g chi.Router) {
		for _, mw := range mws {
			g.Use(mw)
		}
		g.Get("/api/v1/container/images", a.handleListImages)
		g.Post("/api/v1/container/scan", a.handleScan)
		g.Get("/api/v1/container/scan/{id}", a.handleGetScan)
		g.Post("/api/v1/container/seed", a.handleSeed)
	})
}

func (a *API) handleListImages(w http.ResponseWriter, r *http.Request) {
	imgs := a.scanner.ListImages()
	writeJSON(w, http.StatusOK, imgs)
}

func (a *API) handleScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ref string `json:"ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Ref == "" {
		writeError(w, http.StatusBadRequest, "field 'ref' required")
		return
	}
	id := a.scanner.ScanAsync(req.Ref)
	writeJSON(w, http.StatusAccepted, map[string]string{
		"id": id, "status": "scanning", "ref": req.Ref,
	})
}

func (a *API) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	result, ok := a.scanner.GetResult(id)
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found: "+id)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *API) handleSeed(w http.ResponseWriter, r *http.Request) {
	demoImages := []string{
		"redis:7-alpine",
		"nginx:1.25-alpine",
		"alpine:3.19",
		"busybox:1.36",
	}
	ids := make([]string, 0, len(demoImages))
	for _, ref := range demoImages {
		ids = append(ids, a.scanner.ScanAsync(ref))
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"queued": ids,
		"images": demoImages,
		"note":   "Scans running in background. Poll GET /api/v1/container/images.",
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
