// Package handler — real ConMon score (Sprint 7.4).
//
// Pre-Sprint-7 the dashboard rendered "ConMon 94/100" from a hardcoded
// string in p4_compliance.html — a demo number that bore no relation to
// observable system state. Auditors who read the marketing slides
// expected an evidence trail; the dashboard offered none.
//
// This endpoint computes a real ConMon score from the same signals
// cATO posture already uses, returning both the numeric score and the
// per-criterion breakdown so the dashboard tooltip can explain WHY
// the score is what it is. The score and the gate-derived "Security
// Posture Score" (gate.Score) are SEPARATE — they measure different
// things:
//
//   • Posture Score (gate.Score) — point-in-time scan finding posture.
//     Answers "how vulnerable is the codebase right now?".
//   • ConMon Score (this file)  — operational maturity over time.
//     Answers "are we doing continuous monitoring properly?".
//
// Reconciliation: the response includes an `explanation` field the UI
// surfaces as a tooltip so users don't read 30/100 next to 94/100 and
// assume the dashboard is broken.
//
// GET /api/v1/conmon/score
package handler

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type ConMonScore struct {
	DB *store.DB
}

func NewConMonScore(db *store.DB) *ConMonScore { return &ConMonScore{DB: db} }

type conmonCriterion struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Points int    `json:"points"`     // points awarded (0..weight)
	Weight int    `json:"weight"`     // max possible
	Detail string `json:"detail"`
}

func (h *ConMonScore) Get(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}

	criteria := []conmonCriterion{
		h.scoreScanCadence(r, tenantID),       // 25pts
		h.scoreDriftAck(r, tenantID),          // 20pts
		h.scoreEvidenceFreshness(r, tenantID), // 15pts
		h.scoreAuditChain(r, tenantID),        // 15pts
		h.scorePOAM(r, tenantID),              // 15pts
		h.scoreIncidentReporting(r, tenantID), // 10pts
	}
	total, max := 0, 0
	for _, c := range criteria {
		total += c.Points
		max += c.Weight
	}
	score := 0
	if max > 0 {
		score = (total * 100) / max
	}

	jsonOK(w, map[string]any{
		"score":    score,
		"criteria": criteria,
		"explanation": "ConMon Score reflects operational continuous-" +
			"monitoring maturity (scan cadence, drift handling, evidence " +
			"freshness, audit chain integrity). It is INTENTIONALLY distinct " +
			"from the Posture Score, which reflects point-in-time scan " +
			"findings. A high ConMon Score with a low Posture Score is " +
			"normal: it means you are monitoring well but currently have " +
			"unresolved findings.",
	})
}

// ── individual criterion scorers ────────────────────────────────────────────
//
// Each returns a conmonCriterion with Points ≤ Weight. Implementations
// keep the queries cheap and tenant-scoped — this endpoint is hit on
// every dashboard render.

func (h *ConMonScore) scoreScanCadence(r *http.Request, tenantID string) conmonCriterion {
	const weight = 25
	var n int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM runs
		  WHERE tenant_id = $1 AND status = 'COMPLETED'
		    AND finished_at > NOW() - INTERVAL '7 days'`,
		tenantID).Scan(&n)
	switch {
	case n >= 5:
		return conmonCriterion{ID: "scan_cadence", Label: "Scan cadence (≥5/wk)",
			Points: weight, Weight: weight,
			Detail: itoa(n) + " completed scans in last 7 days"}
	case n >= 1:
		// Partial credit so a tenant doing 1-2 scans/week isn't tagged
		// the same as a tenant doing 0.
		pts := weight * n / 5
		return conmonCriterion{ID: "scan_cadence", Label: "Scan cadence (≥5/wk)",
			Points: pts, Weight: weight,
			Detail: itoa(n) + " completed scans in last 7 days (target: 5)"}
	default:
		return conmonCriterion{ID: "scan_cadence", Label: "Scan cadence (≥5/wk)",
			Points: 0, Weight: weight,
			Detail: "no completed scans in last 7 days"}
	}
}

func (h *ConMonScore) scoreDriftAck(r *http.Request, tenantID string) conmonCriterion {
	const weight = 20
	var stale, total int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT
		   COUNT(*) FILTER (WHERE acknowledged_at IS NULL
		                    AND detected_at < NOW() - INTERVAL '72 hours'),
		   COUNT(*)
		 FROM conmon_deviations
		 WHERE tenant_id = $1
		   AND detected_at > NOW() - INTERVAL '30 days'`,
		tenantID).Scan(&stale, &total)
	if total == 0 {
		// No drift events in window — full credit, defensible: nothing to
		// fail to acknowledge.
		return conmonCriterion{ID: "drift_ack", Label: "Drift ack within 72h",
			Points: weight, Weight: weight,
			Detail: "no drift events in last 30 days"}
	}
	if stale == 0 {
		return conmonCriterion{ID: "drift_ack", Label: "Drift ack within 72h",
			Points: weight, Weight: weight,
			Detail: "all " + itoa(total) + " drift events acknowledged within SLA"}
	}
	// Linear penalty: lose 4pts per stale event up to weight.
	pts := weight - 4*stale
	if pts < 0 {
		pts = 0
	}
	return conmonCriterion{ID: "drift_ack", Label: "Drift ack within 72h",
		Points: pts, Weight: weight,
		Detail: itoa(stale) + " of " + itoa(total) + " drift events past 72h SLA"}
}

func (h *ConMonScore) scoreEvidenceFreshness(r *http.Request, tenantID string) conmonCriterion {
	const weight = 15
	var lastUp *time.Time
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT MAX(uploaded_at) FROM compliance_evidence WHERE tenant_id = $1`,
		tenantID).Scan(&lastUp)
	if lastUp == nil {
		return conmonCriterion{ID: "evidence_freshness", Label: "Evidence within 30d",
			Points: 0, Weight: weight, Detail: "no evidence uploads recorded"}
	}
	age := time.Since(*lastUp)
	switch {
	case age < 30*24*time.Hour:
		return conmonCriterion{ID: "evidence_freshness", Label: "Evidence within 30d",
			Points: weight, Weight: weight,
			Detail: "last upload " + humanAge(age) + " ago"}
	case age < 60*24*time.Hour:
		return conmonCriterion{ID: "evidence_freshness", Label: "Evidence within 30d",
			Points: weight / 2, Weight: weight,
			Detail: "last upload " + humanAge(age) + " ago (target: 30d)"}
	default:
		return conmonCriterion{ID: "evidence_freshness", Label: "Evidence within 30d",
			Points: 0, Weight: weight,
			Detail: "last upload " + humanAge(age) + " ago — overdue"}
	}
}

func (h *ConMonScore) scoreAuditChain(r *http.Request, tenantID string) conmonCriterion {
	const weight = 15
	var brokenCount int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM audit_log
		  WHERE tenant_id = $1 AND action = 'CHAIN_BROKEN'
		    AND created_at > NOW() - INTERVAL '30 days'`,
		tenantID).Scan(&brokenCount)
	if brokenCount == 0 {
		return conmonCriterion{ID: "audit_chain", Label: "Audit chain integrity (30d)",
			Points: weight, Weight: weight,
			Detail: "no chain breaks recorded"}
	}
	return conmonCriterion{ID: "audit_chain", Label: "Audit chain integrity (30d)",
		Points: 0, Weight: weight,
		Detail: itoa(brokenCount) + " chain break(s) in last 30 days"}
}

func (h *ConMonScore) scorePOAM(r *http.Request, tenantID string) conmonCriterion {
	const weight = 15
	var overdue int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM findings
		  WHERE tenant_id = $1 AND severity = 'critical'
		    AND created_at < NOW() - INTERVAL '30 days'`,
		tenantID).Scan(&overdue)
	if overdue == 0 {
		return conmonCriterion{ID: "poam", Label: "POA&M (no critical >30d)",
			Points: weight, Weight: weight,
			Detail: "no overdue critical findings"}
	}
	pts := weight - 3*overdue
	if pts < 0 {
		pts = 0
	}
	return conmonCriterion{ID: "poam", Label: "POA&M (no critical >30d)",
		Points: pts, Weight: weight,
		Detail: itoa(overdue) + " critical finding(s) open > 30 days"}
}

func (h *ConMonScore) scoreIncidentReporting(r *http.Request, tenantID string) conmonCriterion {
	const weight = 10
	var missing int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM ir_incidents i
		  WHERE i.tenant_id = $1 AND i.is_substantial = true
		    AND i.detected_at < NOW() - INTERVAL '72 hours'
		    AND NOT EXISTS (
		      SELECT 1 FROM circia_reports c
		      WHERE c.incident_id = i.id AND c.tenant_id = i.tenant_id
		    )`,
		tenantID).Scan(&missing)
	if missing == 0 {
		return conmonCriterion{ID: "incident_reporting",
			Label: "CIRCIA 72h reporting", Points: weight, Weight: weight,
			Detail: "all substantial incidents reported on time"}
	}
	return conmonCriterion{ID: "incident_reporting",
		Label: "CIRCIA 72h reporting", Points: 0, Weight: weight,
		Detail: itoa(missing) + " substantial incident(s) past 72h deadline"}
}
