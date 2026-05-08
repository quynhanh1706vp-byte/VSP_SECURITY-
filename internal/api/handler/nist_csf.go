// Package handler — NIST CSF 2.0 organisational profile.
//
// Reference: NIST Cybersecurity Framework 2.0 (Feb 2024).
// Six functions (Govern + Identify + Protect + Detect + Respond + Recover),
// 22 categories. Each category gets a maturity tier (1 Partial → 4 Adaptive)
// computed from VSP evidence — this is an Organisational Profile in CSF
// terminology, suitable for inclusion in regulatory submissions or RFP
// responses ("yes, here's our NIST CSF profile").
//
// GET /api/v1/nist-csf/profile
//
// Output is a structured Organisational Profile JSON the customer can
// submit verbatim or merge into their own CSF documentation. Self-
// attested — third-party validation requires an external assessor
// (which is why the JSON includes an `attested_by: VSP-self` field).
package handler

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type NISTCSF struct {
	DB *store.DB
}

func NewNISTCSF(db *store.DB) *NISTCSF { return &NISTCSF{DB: db} }

type csfCategory struct {
	ID          string   `json:"id"`        // e.g. "GV.OC"
	Name        string   `json:"name"`
	Function    string   `json:"function"`  // GV | ID | PR | DE | RS | RC
	Tier        int      `json:"tier"`      // 1..4
	TierLabel   string   `json:"tier_label"`
	Evidence    []string `json:"evidence"`
}

func tierLabel(t int) string {
	switch t {
	case 4:
		return "Adaptive"
	case 3:
		return "Repeatable"
	case 2:
		return "Risk Informed"
	case 1:
		return "Partial"
	}
	return "n/a"
}

// Profile returns the VSP self-attested NIST CSF 2.0 profile.
func (h *NISTCSF) Profile(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.FromContext(r.Context()); !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	cats := buildCSFCategories()
	tierSum := 0
	for _, c := range cats {
		tierSum += c.Tier
	}
	avgTier := float64(tierSum) / float64(len(cats))

	jsonOK(w, map[string]any{
		"framework":      "NIST CSF 2.0 (February 2024)",
		"profile_type":   "Organisational Profile (Current State)",
		"attested_by":    "VSP-self",
		"attested_at":    time.Now().UTC().Format(time.RFC3339),
		"caveat":         "Self-attestation. Third-party validation by 3PAO planned Q3 2026.",
		"functions": []map[string]any{
			{"id": "GV", "name": "Govern", "categories_total": 5},
			{"id": "ID", "name": "Identify", "categories_total": 3},
			{"id": "PR", "name": "Protect", "categories_total": 5},
			{"id": "DE", "name": "Detect", "categories_total": 3},
			{"id": "RS", "name": "Respond", "categories_total": 4},
			{"id": "RC", "name": "Recover", "categories_total": 2},
		},
		"categories":     cats,
		"average_tier":   avgTier,
		"tier_breakdown": map[string]int{
			"1_partial":      countByTier(cats, 1),
			"2_risk_inf":     countByTier(cats, 2),
			"3_repeatable":   countByTier(cats, 3),
			"4_adaptive":     countByTier(cats, 4),
		},
	})
}

func countByTier(cats []csfCategory, t int) int {
	n := 0
	for _, c := range cats {
		if c.Tier == t {
			n++
		}
	}
	return n
}

// buildCSFCategories — 22 NIST CSF 2.0 categories with VSP evidence
// pinned. Tier reflects current state, not target. Update when new
// controls land.
func buildCSFCategories() []csfCategory {
	return []csfCategory{
		// ── GOVERN ──────────────────────────────────────────────────
		{ID: "GV.OC", Name: "Organizational Context", Function: "GV", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"docs/ARCHITECTURE.md", "docs/SECURITY_DECISIONS.md"}},
		{ID: "GV.RM", Name: "Risk Management Strategy", Function: "GV", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"docs/SPRINT_2026Q2_FINAL_REPORT.md risk register"}},
		{ID: "GV.RR", Name: "Roles, Responsibilities, Authorities", Function: "GV", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{".github/CODEOWNERS — 22 paths"}},
		{ID: "GV.PO", Name: "Policy", Function: "GV", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"docs/security/VULNERABILITY_DISCLOSURE_POLICY.md", "/.well-known/security.txt"}},
		{ID: "GV.OV", Name: "Oversight", Function: "GV", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"GET /api/v1/audit/bundle", "GET /api/v1/improvement/quarters"}},

		// ── IDENTIFY ────────────────────────────────────────────────
		{ID: "ID.AM", Name: "Asset Management", Function: "ID", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"internal/api/handler/assets.go", "syft SBOM generator"}},
		{ID: "ID.RA", Name: "Risk Assessment", Function: "ID", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"26 scanner integrations + EPSS/KEV enrichment"}},
		{ID: "ID.IM", Name: "Improvement", Function: "ID", Tier: 4, TierLabel: tierLabel(4),
			Evidence: []string{"GET /api/v1/improvement/quarters (DSOMM L4 trend evidence)"}},

		// ── PROTECT ─────────────────────────────────────────────────
		{ID: "PR.AA", Name: "Identity & Authentication", Function: "PR", Tier: 4, TierLabel: tierLabel(4),
			Evidence: []string{"WebAuthn + TOTP + HIBP + IP lockout + UEBA-driven session revoke"}},
		{ID: "PR.AT", Name: "Awareness & Training", Function: "PR", Tier: 2, TierLabel: tierLabel(2),
			Evidence: []string{"Tabletop exercise registry (8 scenarios) — schedule pending"}},
		{ID: "PR.DS", Name: "Data Security", Function: "PR", Tier: 4, TierLabel: tierLabel(4),
			Evidence: []string{"Postgres RLS on 9 tables + DSAR/erasure + Vault secrets"}},
		{ID: "PR.PS", Name: "Platform Security", Function: "PR", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"Helm chart restricted PodSecurityContext + NetworkPolicy"}},
		{ID: "PR.IR", Name: "Infrastructure Resilience", Function: "PR", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"HPA + PDB + multi-region residency"}},

		// ── DETECT ──────────────────────────────────────────────────
		{ID: "DE.CM", Name: "Continuous Monitoring", Function: "DE", Tier: 4, TierLabel: tierLabel(4),
			Evidence: []string{"ConMon drift detection + cATO + GET /api/v1/conmon/score"}},
		{ID: "DE.AE", Name: "Adverse Event Analysis", Function: "DE", Tier: 4, TierLabel: tierLabel(4),
			Evidence: []string{"UEBA 7 anomaly types + correlation engine + KPI watchdog"}},
		{ID: "DE.DP", Name: "Detection Processes", Function: "DE", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"SIEM correlation rules + threat intel feeds"}},

		// ── RESPOND ─────────────────────────────────────────────────
		{ID: "RS.MA", Name: "Incident Management", Function: "RS", Tier: 4, TierLabel: tierLabel(4),
			Evidence: []string{"NIST 800-61r3 lifecycle in ir_incidents + CIRCIA 72h reporting"}},
		{ID: "RS.AN", Name: "Incident Analysis", Function: "RS", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"Forensics evidence preservation + SOAR playbook engine"}},
		{ID: "RS.CO", Name: "Incident Response Communications", Function: "RS", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"Notification fan-out (Slack/Teams/PagerDuty) + signed webhooks"}},
		{ID: "RS.MI", Name: "Incident Mitigation", Function: "RS", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"SOAR auto-response + autopr/ remediation PRs"}},

		// ── RECOVER ─────────────────────────────────────────────────
		{ID: "RC.RP", Name: "Incident Recovery Plan Execution", Function: "RC", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"docs/RUNBOOK.md + recovered_at lifecycle phase"}},
		{ID: "RC.CO", Name: "Incident Recovery Communications", Function: "RC", Tier: 3, TierLabel: tierLabel(3),
			Evidence: []string{"GET /api/v1/status (public) + transparency report generator"}},
	}
}
