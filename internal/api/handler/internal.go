package handler

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/gate"
	"github.com/vsp/platform/internal/scanner"
	"github.com/vsp/platform/internal/store"
)

// InternalScan handles callbacks from the scanner worker.
// POST /internal/scan/complete
type InternalScan struct {
	DB *store.DB
}

type ScanCompletePayload struct {
	RID        string           `json:"rid"`
	TenantID   string           `json:"tenant_id"`
	Findings   []store.Finding  `json:"findings"`
	ToolErrors map[string]string `json:"tool_errors"`
	DurationMs int64            `json:"duration_ms"`
}

func (h *InternalScan) Complete(w http.ResponseWriter, r *http.Request) {
	// Auth: internal endpoint chỉ được gọi từ scanner worker
	// Validate bằng INTERNAL_SECRET header
	secret := os.Getenv("INTERNAL_SECRET")
	if secret == "" { secret = "dev-internal-secret" }
	if r.Header.Get("X-Internal-Secret") != secret {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	var payload ScanCompletePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		jsonError(w, "invalid payload", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// 1. Insert findings
	if err := h.DB.InsertFindingsBatch(ctx, payload.Findings); err != nil {
		log.Error().Err(err).Str("rid", payload.RID).Msg("insert findings failed")
		jsonError(w, "insert findings failed", http.StatusInternalServerError)
		return
	}

	// 2. Build summary
	sev := make(map[string]int)
	hasSecrets := false
	for _, f := range payload.Findings {
		sev[f.Severity]++
		if f.Tool == "gitleaks" { hasSecrets = true }
	}
	s := scanner.Summary{
		Critical:   sev["CRITICAL"],
		High:       sev["HIGH"],
		Medium:     sev["MEDIUM"],
		Low:        sev["LOW"],
		Info:       sev["INFO"],
		HasSecrets: hasSecrets,
	}

	// 3. Evaluate gate
	rule := gate.DefaultRule()
	result := gate.Evaluate(rule, s)

	// 4. Build summary JSON
	summaryJSON, _ := json.Marshal(map[string]int{
		"CRITICAL": s.Critical,
		"HIGH":     s.High,
		"MEDIUM":   s.Medium,
		"LOW":      s.Low,
		"INFO":     s.Info,
	})

	// 5. Update run record
	if err := h.DB.UpdateRunResult(ctx, payload.TenantID, payload.RID,
		string(result.Decision), result.Posture,
		len(payload.Findings), summaryJSON); err != nil {
		log.Error().Err(err).Str("rid", payload.RID).Msg("update run result failed")
	}

	log.Info().
		Str("rid", payload.RID).
		Int("findings", len(payload.Findings)).
		Str("gate", string(result.Decision)).
		Str("posture", result.Posture).
		Msg("scan complete")

	jsonOK(w, map[string]any{
		"ok":       true,
		"rid":      payload.RID,
		"gate":     result.Decision,
		"posture":  result.Posture,
		"score":    result.Score,
		"findings": len(payload.Findings),
	})
}
