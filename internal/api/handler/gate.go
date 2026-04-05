package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/gate"
	"github.com/vsp/platform/internal/scanner"
	"github.com/vsp/platform/internal/store"
)

type Gate struct {
	DB *store.DB
}

// GET /api/v1/vsp/gate/latest
func (h *Gate) Latest(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	run, err := h.DB.GetLatestRun(r.Context(), claims.TenantID)
	if err != nil || run == nil {
		jsonError(w, "no runs found", http.StatusNotFound)
		return
	}
	s := runSummary(run)
	jsonOK(w, map[string]any{
		"rid":     run.RID,
		"gate":    run.Gate,
		"posture": run.Posture,
		"score":   gate.Score(s),
		"status":  run.Status,
	})
}

// GET /api/v1/vsp/posture/latest
func (h *Gate) PostureLatest(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	run, err := h.DB.GetLatestRun(r.Context(), claims.TenantID)
	if err != nil || run == nil {
		jsonError(w, "no runs found", http.StatusNotFound)
		return
	}
	s := runSummary(run)
	jsonOK(w, map[string]any{
		"grade":    gate.Posture(s),
		"score":    gate.Score(s),
		"rid":      run.RID,
		"critical": s.Critical,
		"high":     s.High,
		"medium":   s.Medium,
		"low":      s.Low,
	})
}

// POST /api/v1/policy/evaluate
func (h *Gate) Evaluate(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	var req struct {
		Repo      string `json:"repo"`
		CommitSHA string `json:"commit_sha"`
		RID       string `json:"rid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}

	var run *store.Run
	var err error
	if req.RID != "" {
		run, err = h.DB.GetRunByRID(r.Context(), claims.TenantID, req.RID)
	} else {
		run, err = h.DB.GetLatestRun(r.Context(), claims.TenantID)
	}
	if err != nil || run == nil {
		jsonError(w, "no run found to evaluate", http.StatusNotFound)
		return
	}

	rules, _ := h.DB.ListPolicyRules(r.Context(), claims.TenantID)
	policyRule := gate.DefaultRule()
	if len(rules) > 0 {
		r0 := rules[0]
		policyRule = gate.PolicyRule{
			FailOn:        r0.FailOn,
			MinScore:      r0.MinScore,
			MaxHigh:       r0.MaxHigh,
			BlockSecrets:  r0.BlockSecrets,
			BlockCritical: r0.BlockCritical,
		}
	}

	s := runSummary(run)
	result := gate.Evaluate(policyRule, s)

	jsonOK(w, map[string]any{
		"decision": result.Decision,
		"reason":   result.Reason,
		"score":    result.Score,
		"posture":  result.Posture,
		"rid":      run.RID,
		"repo":     req.Repo,
		"summary":  s,
	})
}

// GET /api/v1/policy/rules
func (h *Gate) ListRules(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rules, err := h.DB.ListPolicyRules(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if rules == nil {
		rules = []store.PolicyRule{}
	}
	jsonOK(w, map[string]any{"rules": rules, "total": len(rules)})
}

// POST /api/v1/policy/rules
func (h *Gate) CreateRule(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req store.PolicyRule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	req.TenantID = claims.TenantID
	if req.Name == ""        { req.Name = "default" }
	if req.RepoPattern == "" { req.RepoPattern = "*" }
	if req.FailOn == ""      { req.FailOn = "FAIL" }
	if req.MaxHigh == 0      { req.MaxHigh = -1 }
	req.BlockCritical = true
	req.BlockSecrets  = true

	rule, err := h.DB.CreatePolicyRule(r.Context(), req)
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, rule)
}

// DELETE /api/v1/policy/rules/{id}
func (h *Gate) DeleteRule(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	h.DB.DeletePolicyRule(r.Context(), claims.TenantID, id) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

// runSummary converts store.Run summary JSON to scanner.Summary
func runSummary(run *store.Run) scanner.Summary {
	if run == nil {
		return scanner.Summary{}
	}
	// Use map[string]any to handle mixed types (int + bool + string)
	var m map[string]any
	if err := json.Unmarshal(run.Summary, &m); err != nil {
		return scanner.Summary{}
	}
	toInt := func(v any) int {
		switch n := v.(type) {
		case int:    return n
		case float64: return int(n)
		default:     return 0
		}
	}
	toBool := func(v any) bool {
		b, ok := v.(bool); return ok && b
	}
	return scanner.Summary{
		Critical:   toInt(m["CRITICAL"]),
		High:       toInt(m["HIGH"]),
		Medium:     toInt(m["MEDIUM"]),
		Low:        toInt(m["LOW"]),
		Info:       toInt(m["INFO"]),
		HasSecrets: toBool(m["HAS_SECRETS"]),
	}
}
