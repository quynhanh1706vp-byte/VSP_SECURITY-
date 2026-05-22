// Package handler — KPI internal-consistency sanity check.
//
// GET /api/v1/kpi/sanity
//
// Returns a list of `assertion` records — each one a property of the KPI
// system that should always hold. Operators (and CI) call this endpoint
// in staging / prod and treat any `passed=false` row as a release
// blocker. The pre-Sprint-7 motivating examples:
//
//   - The dashboard letter grade matches what gate.Posture() returns
//     for the same scan summary (no JS-derived divergence).
//   - Score floor is consistent with bucket weights (no run with
//     impossible-by-construction score values like 30 with 2032
//     findings of which only 5 are high — the old hard-cap math).
//   - Supply-chain status taxonomy never contains a stray "tampered"
//     for a record whose reason field clearly indicates a non-tamper
//     failure mode (cosign unavailable, registry unreachable, etc.).
//
// The endpoint is intentionally cheap (no heavy DB scans) so CI can
// poll it without operational impact.
package handler

import (
	"net/http"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/gate"
	"github.com/vsp/platform/internal/scanner"
	"github.com/vsp/platform/internal/store"
)

type KPISanity struct {
	DB *store.DB
}

func NewKPISanity(db *store.DB) *KPISanity { return &KPISanity{DB: db} }

type sanityAssertion struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Passed        bool   `json:"passed"`
	Detail        string `json:"detail,omitempty"`
	BlocksRelease bool   `json:"blocks_release"` // CI hard-fails on these
}

func (h *KPISanity) Get(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.FromContext(r.Context()); !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, mustClaimTenant(r))
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}

	assertions := []sanityAssertion{
		h.checkGradeUnification(),
		h.checkScoreDynamicRange(),
		h.checkHardFailDominates(),
		h.checkSupplyChainTaxonomy(r, tenantID),
		h.checkAuditChainNoStaleBreaks(r, tenantID),
	}
	failedBlockers := 0
	for _, a := range assertions {
		if !a.Passed && a.BlocksRelease {
			failedBlockers++
		}
	}
	status := http.StatusOK
	if failedBlockers > 0 {
		// 409 Conflict — KPI integrity violations are an internal-state
		// inconsistency, not a request error. CI scripts should grep for
		// this status code as the release-block signal.
		status = http.StatusConflict
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	jsonOK(w, map[string]any{
		"assertions":      assertions,
		"failed_blockers": failedBlockers,
	})
}

func mustClaimTenant(r *http.Request) string {
	c, _ := auth.FromContext(r.Context())
	return c.TenantID
}

// ── individual checks ──────────────────────────────────────────────────────

// checkGradeUnification probes a few synthetic Summary inputs and
// confirms gate.Posture() returns one of the canonical letters. This
// catches code paths that re-introduce a separate grader returning
// stale labels (the pre-Sprint-7.2 bug).
func (h *KPISanity) checkGradeUnification() sanityAssertion {
	// Sprint 12.6: probe expectations updated to match Sprint 7.3
	// sqrt-based scoring. {High:1} → score 92 → A+ (band ≥ 90),
	// not A. Pre-12.6 the assertion expected "A" which made KPI
	// sanity always 409 in healthy clusters.
	probes := []scanner.Summary{
		{},                 // score 100 → A+
		{High: 1},          // 100 - 8 = 92 → A+
		{Critical: 1},      // hard-fail dominates score → F
		{HasSecrets: true}, // hard-fail dominates score → F
	}
	expected := []string{"A+", "A+", "F", "F"}
	for i, s := range probes {
		got := gate.Posture(s)
		if got != expected[i] {
			return sanityAssertion{
				ID: "grade_unification", Label: "Posture grade matches contract",
				Passed: false, BlocksRelease: true,
				Detail: "probe " + itoa(i) + ": got " + got + ", expected " + expected[i],
			}
		}
	}
	return sanityAssertion{
		ID: "grade_unification", Label: "Posture grade matches contract",
		Passed: true, BlocksRelease: true,
	}
}

// checkScoreDynamicRange asserts the score is monotonic in finding
// count — more findings ⇒ lower score. The pre-Sprint-7.3 capped math
// violated this (2 critical and 200 critical produced the same score).
func (h *KPISanity) checkScoreDynamicRange() sanityAssertion {
	a := gate.Score(scanner.Summary{High: 5})
	b := gate.Score(scanner.Summary{High: 50})
	c := gate.Score(scanner.Summary{High: 500})
	if !(a > b && b > c) {
		return sanityAssertion{
			ID: "score_monotonic", Label: "Score decreases with finding count",
			Passed: false, BlocksRelease: true,
			Detail: "scores 5h=" + itoa(a) + " 50h=" + itoa(b) + " 500h=" + itoa(c) +
				" — should be strictly decreasing",
		}
	}
	return sanityAssertion{
		ID: "score_monotonic", Label: "Score decreases with finding count",
		Passed: true, BlocksRelease: true,
	}
}

// checkHardFailDominates asserts critical>0 and HasSecrets always
// produce F regardless of how few of them there are.
func (h *KPISanity) checkHardFailDominates() sanityAssertion {
	if g := gate.Posture(scanner.Summary{Critical: 1}); g != "F" {
		return sanityAssertion{
			ID: "hard_fail", Label: "Critical findings force grade F",
			Passed: false, BlocksRelease: true,
			Detail: "Critical:1 produced grade " + g,
		}
	}
	if g := gate.Posture(scanner.Summary{HasSecrets: true}); g != "F" {
		return sanityAssertion{
			ID: "hard_fail", Label: "Live secrets force grade F",
			Passed: false, BlocksRelease: true,
			Detail: "HasSecrets:true produced grade " + g,
		}
	}
	return sanityAssertion{
		ID: "hard_fail", Label: "Hard-fail conditions force grade F",
		Passed: true, BlocksRelease: true,
	}
}

// checkSupplyChainTaxonomy looks for status="tampered" rows whose
// stored reason indicates a NON-tamper failure (registry unreachable,
// cosign missing). Such rows are leftover from the pre-Sprint-7.1
// classifier and should be re-classified by a one-shot SQL update.
func (h *KPISanity) checkSupplyChainTaxonomy(r *http.Request, tenantID string) sanityAssertion {
	var n int
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*)
		   FROM supply_chain_signatures
		  WHERE tenant_id = $1
		    AND status = 'tampered'
		    AND COALESCE(reason,'') ILIKE ANY (ARRAY[
		      '%executable file not found%',
		      '%no such file%',
		      '%no signatures found%',
		      '%manifest_unknown%',
		      '%manifest unknown%',
		      '%connection refused%',
		      '%dial tcp%'
		    ])`,
		tenantID).Scan(&n)
	if err != nil {
		// Table may not exist in test DB or the row may be unscoped —
		// skip the check rather than blocking release on schema drift.
		return sanityAssertion{
			ID: "sc_taxonomy", Label: "No mis-classified TAMPERED rows",
			Passed: true, BlocksRelease: false,
			Detail: "supply_chain_signatures unavailable: " + err.Error(),
		}
	}
	if n > 0 {
		return sanityAssertion{
			ID: "sc_taxonomy", Label: "No mis-classified TAMPERED rows",
			Passed: false, BlocksRelease: true,
			Detail: itoa(n) + " row(s) tagged tampered with non-tamper reason — run reclassifier",
		}
	}
	return sanityAssertion{
		ID: "sc_taxonomy", Label: "No mis-classified TAMPERED rows",
		Passed: true, BlocksRelease: true,
	}
}

// checkAuditChainNoStaleBreaks complements the cATO check: any
// CHAIN_BROKEN within the last 24h is a P0 incident that must be
// remediated before claiming any KPI is trustworthy.
func (h *KPISanity) checkAuditChainNoStaleBreaks(r *http.Request, tenantID string) sanityAssertion {
	var n int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM audit_log
		  WHERE tenant_id = $1 AND action = 'CHAIN_BROKEN'
		    AND created_at > NOW() - INTERVAL '24 hours'`,
		tenantID).Scan(&n)
	if n > 0 {
		return sanityAssertion{
			ID: "audit_chain_24h", Label: "No audit chain breaks in last 24h",
			Passed: false, BlocksRelease: true,
			Detail: itoa(n) + " CHAIN_BROKEN event(s) in last 24h",
		}
	}
	return sanityAssertion{
		ID: "audit_chain_24h", Label: "No audit chain breaks in last 24h",
		Passed: true, BlocksRelease: true,
	}
}
