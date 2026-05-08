// Package handler — vulnerability disclosure intake (RFC 9116 + VDP).
//
// Three endpoints:
//   POST /api/v1/security/disclose       — anonymous researcher intake
//   GET  /api/v1/security/disclosures    — admin: list reports + SLA state
//   POST /api/v1/security/disclosures/{id}/transition — admin: triage workflow
//
// SLA contract is anchored to the published Vulnerability Disclosure
// Policy (docs/security/VULNERABILITY_DISCLOSURE_POLICY.md):
//   ack within 1 business day, triage within 5 business days, fix
//   timelines vary by severity. Computing "business day" properly
//   needs a holiday calendar; for v1 we approximate as 24h × N which
//   is intentionally stricter than the published commitment.
package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

const (
	ackSLA    = 24 * time.Hour     // VDP "1 business day"
	triageSLA = 5 * 24 * time.Hour // VDP "5 business days"
)

// fixSLAByseverity returns the fix-by deadline relative to triage time.
// Mirrors the table in the published VDP — keep these in lockstep.
func fixSLAByseverity(sev string) time.Duration {
	switch strings.ToLower(sev) {
	case "critical":
		return 14 * 24 * time.Hour
	case "high":
		return 30 * 24 * time.Hour
	case "medium":
		return 60 * 24 * time.Hour
	case "low":
		return 90 * 24 * time.Hour
	}
	return 0
}

type Disclosure struct {
	DB *store.DB
}

func NewDisclosure(db *store.DB) *Disclosure { return &Disclosure{DB: db} }

// Submit is unauthenticated — researchers don't have VSP accounts.
// Caller still passes through the global rate limiter so a flood of
// junk reports doesn't fill the table.
func (h *Disclosure) Submit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ReporterName   string  `json:"reporter_name"`
		ReporterEmail  string  `json:"reporter_email"`
		ReporterHandle string  `json:"reporter_handle"`
		Title          string  `json:"title"`
		Body           string  `json:"body"`
		Affected       string  `json:"affected"`
		CVSSv3         float64 `json:"cvss_v3"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	body.ReporterEmail = strings.TrimSpace(body.ReporterEmail)
	body.Title = strings.TrimSpace(body.Title)
	body.Body = strings.TrimSpace(body.Body)
	if body.ReporterEmail == "" || !strings.Contains(body.ReporterEmail, "@") {
		jsonError(w, "valid reporter_email required", http.StatusBadRequest)
		return
	}
	if body.Title == "" || len(body.Title) > 200 {
		jsonError(w, "title required (1-200 chars)", http.StatusBadRequest)
		return
	}
	if body.Body == "" || len(body.Body) > 64*1024 {
		jsonError(w, "body required (1-65536 chars)", http.StatusBadRequest)
		return
	}
	if body.CVSSv3 < 0 || body.CVSSv3 > 10 {
		jsonError(w, "cvss_v3 out of range", http.StatusBadRequest)
		return
	}
	hash := sha256.Sum256([]byte(body.Body))
	hashHex := hex.EncodeToString(hash[:])

	// Dedup: same body within 7 days = duplicate.
	var existingPub *string
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT public_ref FROM security_disclosures
		  WHERE body_sha256 = $1 AND submitted_at > NOW() - INTERVAL '7 days'
		  LIMIT 1`, hashHex).Scan(&existingPub)
	if existingPub != nil {
		// Friendly response: we already have this; don't reveal the
		// public_ref to a fresh submitter (it might leak triage state).
		jsonOK(w, map[string]any{
			"status": "received",
			"hint":   "thank you — a similar report is already in triage",
		})
		return
	}

	now := time.Now().UTC()
	var id, ref string
	err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO security_disclosures
		   (reporter_name, reporter_email, reporter_handle,
		    title, body, body_sha256, affected, cvss_v3,
		    submitted_at, ack_due_at, triage_due_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, 0)::numeric,
		         $9, $10, $11)
		 RETURNING id, COALESCE(public_ref, '')`,
		body.ReporterName, body.ReporterEmail, body.ReporterHandle,
		body.Title, body.Body, hashHex, body.Affected, body.CVSSv3,
		now, now.Add(ackSLA), now.Add(triageSLA),
	).Scan(&id, &ref)
	if err != nil {
		jsonError(w, "could not record report", http.StatusInternalServerError)
		return
	}
	// Ack receipt — researchers don't need internal IDs but they want
	// confirmation the report landed.
	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, map[string]any{
		"status":          "received",
		"ack_due_at":      now.Add(ackSLA).Format(time.RFC3339),
		"triage_due_at":   now.Add(triageSLA).Format(time.RFC3339),
		"contact":         "security@vsp.vn",
		"policy":          "/security/policy",
	})
}

// List returns disclosures for the security team to triage. Admin only.
func (h *Disclosure) List(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id::text, COALESCE(public_ref,''), reporter_email, title,
		        affected, status, COALESCE(severity,''), cvss_v3,
		        submitted_at, ack_due_at, triage_due_at, fix_due_at,
		        acknowledged_at, triaged_at, resolved_at
		   FROM security_disclosures
		  ORDER BY submitted_at DESC LIMIT 500`)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type item struct {
		ID            string     `json:"id"`
		PublicRef     string     `json:"public_ref,omitempty"`
		Reporter      string     `json:"reporter_email"`
		Title         string     `json:"title"`
		Affected      string     `json:"affected,omitempty"`
		Status        string     `json:"status"`
		Severity      string     `json:"severity,omitempty"`
		CVSS          *float64   `json:"cvss_v3,omitempty"`
		SubmittedAt   time.Time  `json:"submitted_at"`
		AckDueAt      time.Time  `json:"ack_due_at"`
		TriageDueAt   time.Time  `json:"triage_due_at"`
		FixDueAt      *time.Time `json:"fix_due_at,omitempty"`
		AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
		TriagedAt     *time.Time `json:"triaged_at,omitempty"`
		ResolvedAt    *time.Time `json:"resolved_at,omitempty"`
		AckOverdue    bool       `json:"ack_overdue"`
		TriageOverdue bool       `json:"triage_overdue"`
		FixOverdue    bool       `json:"fix_overdue"`
	}
	out := []item{}
	now := time.Now()
	for rows.Next() {
		var it item
		var cvss *float64
		if err := rows.Scan(&it.ID, &it.PublicRef, &it.Reporter, &it.Title,
			&it.Affected, &it.Status, &it.Severity, &cvss,
			&it.SubmittedAt, &it.AckDueAt, &it.TriageDueAt, &it.FixDueAt,
			&it.AcknowledgedAt, &it.TriagedAt, &it.ResolvedAt); err == nil {
			it.CVSS = cvss
			it.AckOverdue = it.AcknowledgedAt == nil && now.After(it.AckDueAt)
			it.TriageOverdue = it.TriagedAt == nil && now.After(it.TriageDueAt)
			it.FixOverdue = it.FixDueAt != nil && it.ResolvedAt == nil && now.After(*it.FixDueAt)
			out = append(out, it)
		}
	}
	jsonOK(w, map[string]any{"disclosures": out, "total": len(out)})
}

// Transition moves a disclosure through the workflow. The handler
// enforces valid state transitions + sets the right timestamp fields
// so the frontend doesn't have to know the workflow rules.
func (h *Disclosure) Transition(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var body struct {
		To       string `json:"to"`       // target status
		Severity string `json:"severity"` // required when transitioning to triaged
		Notes    string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	body.To = strings.ToLower(strings.TrimSpace(body.To))
	allowed := map[string]bool{
		"acknowledged": true, "triaged": true, "resolved": true,
		"disclosed": true, "duplicate": true, "out_of_scope": true,
		"not_an_issue": true,
	}
	if !allowed[body.To] {
		jsonError(w, "unsupported target status", http.StatusBadRequest)
		return
	}

	// Build set-clause based on target status. Each transition assigns
	// the matching timestamp + (for triaged) the severity-derived
	// fix_due_at. Server-driven so a buggy frontend can't desync the
	// SLA columns.
	now := time.Now().UTC()
	var setClause string
	args := []any{body.To, id, now}
	switch body.To {
	case "acknowledged":
		setClause = `status = $1, acknowledged_at = $3,
		             public_ref = COALESCE(public_ref, $4)`
		args = append(args, generatePublicRef(now))
	case "triaged":
		if body.Severity == "" || fixSLAByseverity(body.Severity) == 0 {
			jsonError(w, "severity required (critical|high|medium|low)",
				http.StatusBadRequest)
			return
		}
		setClause = `status = $1, triaged_at = $3, severity = $4,
		             fix_due_at = $5`
		args = append(args, body.Severity, now.Add(fixSLAByseverity(body.Severity)))
	case "resolved":
		setClause = `status = $1, resolved_at = $3`
	case "disclosed":
		setClause = `status = $1, disclosed_at = $3`
	default:
		// duplicate / out_of_scope / not_an_issue — terminal, just record status.
		setClause = `status = $1, resolved_at = COALESCE(resolved_at, $3)`
	}
	if body.Notes != "" {
		// Append rather than overwrite so triage history is preserved.
		setClause += `, internal_notes = COALESCE(internal_notes,'') || E'\n' || $` +
			fmt.Sprint(len(args)+1)
		args = append(args, "["+now.Format("2006-01-02 15:04")+"] "+body.Notes)
	}

	tag, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE security_disclosures SET `+setClause+` WHERE id = $2`, args...)
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "disclosure not found", http.StatusNotFound)
		return
	}
	logAudit(r, h.DB, "DISCLOSURE_"+strings.ToUpper(body.To), "security_disclosures/"+id)
	jsonOK(w, map[string]any{"id": id, "status": body.To})
}

// generatePublicRef builds a researcher-facing reference like
// "VSP-VDR-2026-0042". Sequence number resets each calendar year.
// We intentionally use a coarse second-based suffix rather than a DB
// sequence so adversaries can't enumerate the report stream by
// observing reference numbers.
func generatePublicRef(t time.Time) string {
	// 4-digit pseudo-sequence from minute-of-year — enough collision
	// resistance for human-readable identifiers; uniqueness is
	// guaranteed by the UUID PRIMARY KEY anyway.
	minOfYear := t.YearDay()*1440 + t.Hour()*60 + t.Minute()
	return fmt.Sprintf("VSP-VDR-%04d-%04d", t.Year(), minOfYear%10000)
}
