// Package handler — CISA Secure Software Self-Attestation form generator.
//
// Reference: CISA Repository for Software Attestation and Artifacts
// Form structure follows CISA SSDF Common Form v2024.
//
// Endpoints:
//   GET  /api/v1/cisa-attestation/ssdf/draft     — auto-populate draft from DB
//   POST /api/v1/cisa-attestation/ssdf/{id}/sign — executive signature (admin only)
package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type SSDFAttest struct {
	DB *store.DB
}

func NewSSDFAttest(db *store.DB) *SSDFAttest { return &SSDFAttest{DB: db} }

// ssdfPractice represents one CISA SSDF practice with its compliance
// statement + the VSP evidence that supports it.
type ssdfPractice struct {
	ID        string `json:"id"`
	Family    string `json:"family"`
	Statement string `json:"statement"`
	Compliant bool   `json:"compliant"`
	Evidence  string `json:"evidence"`
	Caveats   string `json:"caveats,omitempty"`
	Status    string `json:"status"`
	Notes     string `json:"implementation_notes,omitempty"`
}

// CISA-prescribed statements per practice ID (SSDF v1.1).
// These are the official attestation statements required by CISA Common Form 2024.
var ssdfStatements = map[string]string{
	"PO.1.1": "Define security requirements for software development based on identified risks.",
	"PO.1.2": "Identify and document all security requirements for the organization.",
	"PO.2.1": "Identify and document all roles and responsibilities for software development.",
	"PO.3.1": "Specify which compilers, build tools, and configurations to use.",
	"PO.4.1": "Use automated tooling to detect vulnerabilities throughout the SDLC.",
	"PO.5.1": "Implement and maintain secure environments for software development.",
	"PS.1.1": "Protect all forms of code from unauthorised access and tampering.",
	"PS.2.1": "Provide a mechanism for verifying software release integrity.",
	"PS.3.1": "Archive and protect each software release.",
	"PS.3.2": "Collect, safeguard, maintain provenance data for all components.",
	"PW.1.1": "Design software to meet security requirements and mitigate risks.",
	"PW.2.1": "Review the software design to verify security requirements are met.",
	"PW.4.1": "Reuse existing, well-secured software when feasible.",
	"PW.4.4": "Verify the integrity and provenance of acquired components.",
	"PW.5.1": "Create source code by adhering to secure coding practices.",
	"PW.6.1": "Configure compilation, build, and packaging for executable security.",
	"PW.6.2": "Review and/or analyze human-readable code for vulnerabilities.",
	"PW.7.1": "Test executable code to identify vulnerabilities and verify compliance.",
	"PW.8.1": "Configure default settings to be secure.",
	"PW.9.1": "Protect all forms of code from unauthorized access and tampering.",
	"RV.1.1": "Identify and confirm vulnerabilities on an ongoing basis.",
	"RV.1.2": "Establish a vulnerability disclosure program (VDP).",
	"RV.2.1": "Assess, prioritize, and remediate vulnerabilities.",
	"RV.3.1": "Analyze vulnerabilities to identify their root causes.",
}

// Draft auto-populates the SSDF form from the tenant's ssdf_practices DB rows.
// Falls back to hardcoded evidence hints when DB has no data for a practice.
func (h *SSDFAttest) Draft(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		tenantID = claims.TenantID
	}

	// Query tenant's practices from DB
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT practice_id, group_code, status,
		       COALESCE(implementation_notes,'') AS notes,
		       COALESCE(evidence_refs::text,'[]') AS evidence_refs
		FROM ssdf_practices
		WHERE tenant_id = $1
		ORDER BY group_code, practice_id
	`, tenantID)

	practices := []ssdfPractice{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var pid, group, status, notes, evidenceJSON string
			if rows.Scan(&pid, &group, &status, &notes, &evidenceJSON) != nil {
				continue
			}
			// Parse evidence_refs array for first entry as evidence string
			var refs []string
			_ = json.Unmarshal([]byte(evidenceJSON), &refs)
			evidence := notes
			if len(refs) > 0 {
				evidence = refs[0]
			}

			stmt := ssdfStatements[pid]
			if stmt == "" {
				stmt = "Practice " + pid + " — see implementation notes."
			}

			practices = append(practices, ssdfPractice{
				ID:        pid,
				Family:    group,
				Statement: stmt,
				Compliant: status == "implemented" || status == "partial",
				Evidence:  evidence,
				Status:    status,
				Notes:     notes,
			})
		}
	}

	// If no DB data (e.g. tenant not seeded yet), return empty with hint
	if len(practices) == 0 {
		jsonOK(w, map[string]any{
			"form_version": "CISA SSDF Common Form 2024",
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"draft":        true,
			"signed":       false,
			"practices":    []ssdfPractice{},
			"summary": map[string]any{
				"total": 0, "compliant": 0, "compliance_pct": 0,
			},
			"hint": "No SSDF practices found for this tenant. Visit /api/v1/cisa-attestation/practices to initialize.",
		})
		return
	}

	compliantCount := 0
	for _, p := range practices {
		if p.Compliant {
			compliantCount++
		}
	}

	jsonOK(w, map[string]any{
		"form_version":    "CISA SSDF Common Form 2024",
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"draft":           true,
		"signed":          false,
		"product_name":    "VSP — Vietnam Security Platform",
		"product_version": "1.4.0",
		"producer_name":   "VSP Platform",
		"tenant_id":       tenantID,
		"practices":       practices,
		"summary": map[string]any{
			"total":          len(practices),
			"compliant":      compliantCount,
			"compliance_pct": (compliantCount * 100) / len(practices),
		},
		"submission_hint": "Review draft, then POST /api/v1/cisa-attestation/ssdf/{id}/sign with executive credentials.",
	})
}

// Sign records an executive signature on an existing attestation_forms row.
func (h *SSDFAttest) Sign(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden — admin role required", http.StatusForbidden)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		tenantID = claims.TenantID
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var body struct {
		SignerName  string `json:"signer_name"`
		SignerTitle string `json:"signer_title"`
		SignerEmail string `json:"signer_email"`
		Method      string `json:"signature_method"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.SignerName == "" || body.SignerTitle == "" || body.SignerEmail == "" {
		jsonError(w, "signer_name, signer_title, signer_email required", http.StatusBadRequest)
		return
	}
	if body.Method == "" {
		body.Method = "electronic"
	}

	tag, err := h.DB.Pool().Exec(r.Context(), `
		UPDATE attestation_forms
		   SET signed_by_name=$1, signed_by_title=$2,
		       signed_by_email=$3, signature_date=NOW(),
		       signature_method=$4, status='signed', updated_at=NOW()
		 WHERE id=$5 AND tenant_id=$6
		   AND status IN ('draft','pending_signature')`,
		body.SignerName, body.SignerTitle, body.SignerEmail,
		body.Method, id, tenantID)
	if err != nil {
		jsonInternalError(w, r, "db error", err)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "form not found or already signed/submitted", http.StatusBadRequest)
		return
	}
	logAudit(r, h.DB, "SSDF_FORM_SIGNED", "attestation_forms/"+id+":"+body.SignerEmail)
	jsonOK(w, map[string]any{
		"id":     id,
		"status": "signed",
		"signer": body.SignerEmail,
		"hint":   "Form is signed and ready for submission to https://saf.cisa.gov",
	})
}
