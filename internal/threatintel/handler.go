package threatintel

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vsp/platform/internal/auth"
)

type Handler struct {
	client *Client
}

func NewHandler(client *Client) *Handler {
	return &Handler{client: client}
}

// GET /api/v1/ti/enrich?cve=CVE-2024-45337
func (h *Handler) Enrich(w http.ResponseWriter, r *http.Request) {
	cveID := strings.TrimSpace(r.URL.Query().Get("cve"))
	if cveID == "" {
		http.Error(w, `{"error":"cve param required"}`, 400)
		return
	}
	enr, err := h.client.EnrichCVE(r.Context(), cveID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(502)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "enrichment failed"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enr)
}

// POST /api/v1/ti/enrich/batch
// Body: {"cves":["CVE-2024-45337","CVE-2021-44228"]}
func (h *Handler) EnrichBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CVEs []string `json:"cves"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, 400)
		return
	}
	if len(req.CVEs) == 0 {
		http.Error(w, `{"error":"cves required"}`, 400)
		return
	}
	if len(req.CVEs) > 50 {
		req.CVEs = req.CVEs[:50] // reduce from 100 to 50 — NVD rate limit
	}
	// Validate CVE format before enrichment
	valid := req.CVEs[:0]
	for _, id := range req.CVEs {
		if len(id) > 4 && id[:4] == "CVE-" {
			valid = append(valid, id)
		}
	}
	req.CVEs = valid
	results := h.client.EnrichBatch(r.Context(), req.CVEs)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enrichments": results,
		"total":       len(results),
	})
}

// GET /api/v1/ti/findings — CVE findings enriched với TI data
func (h *Handler) EnrichedFindings(w http.ResponseWriter, r *http.Request) {
	_, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	// Return cached enrichments from DB via raw JSONB field
	// Frontend sẽ call /api/v1/vsp/findings và merge với TI data
	http.Error(w, `{"error":"use /api/v1/ti/enrich?cve=CVE-XXX"}`, 400)
}
