// Package handler — compliance evidence file storage.
//
// Endpoints:
//
//	POST   /api/v1/compliance/evidence       multipart upload (file + control_id + notes)
//	GET    /api/v1/compliance/evidence       list (filter ?control_id=)
//	GET    /api/v1/compliance/evidence/{id}  download (sets Content-Disposition)
//	DELETE /api/v1/compliance/evidence/{id}  remove (admin only)
//
// Storage: bytea blob in Postgres (see migration 030). Max 10 MB per file
// enforced at handler. SHA-256 is computed server-side and exposed so clients
// can verify integrity. Every mutation is audit-logged for FedRAMP AU-2.
package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

const maxEvidenceBytes = 10 * 1024 * 1024 // 10 MB

type ComplianceEvidence struct {
	DB *store.DB
}

func NewComplianceEvidence(db *store.DB) *ComplianceEvidence {
	return &ComplianceEvidence{DB: db}
}

// Upload handles POST /api/v1/compliance/evidence
func (h *ComplianceEvidence) Upload(w http.ResponseWriter, r *http.Request) {
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

	// Cap upload size before parsing so a malicious client can't OOM us.
	r.Body = http.MaxBytesReader(w, r.Body, maxEvidenceBytes+4096)
	if err := r.ParseMultipartForm(maxEvidenceBytes); err != nil { //#nosec G120 -- MaxBytesReader applied line above
		jsonError(w, "upload too large or invalid form (max 10MB)", http.StatusBadRequest)
		return
	}

	controlID := strings.TrimSpace(r.FormValue("control_id"))
	notes := strings.TrimSpace(r.FormValue("notes"))
	if controlID == "" {
		jsonError(w, "control_id required", http.StatusBadRequest)
		return
	}
	if len(controlID) > 64 {
		jsonError(w, "control_id too long", http.StatusBadRequest)
		return
	}
	if len(notes) > 1024 {
		jsonError(w, "notes too long (max 1024)", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "file field required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if header.Size > maxEvidenceBytes {
		jsonError(w, "file too large (max 10MB)", http.StatusBadRequest)
		return
	}
	blob, err := io.ReadAll(io.LimitReader(file, maxEvidenceBytes+1))
	if err != nil {
		jsonError(w, "read file: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(blob) > maxEvidenceBytes {
		jsonError(w, "file too large (max 10MB)", http.StatusBadRequest)
		return
	}

	sum := sha256.Sum256(blob)
	hash := hex.EncodeToString(sum[:])
	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	uploadedBy := resolveUserUUID(r.Context(), h.DB, claims.UserID)
	var uploadedByPtr *string
	if uploadedBy != "" {
		uploadedByPtr = &uploadedBy
	}

	// Upsert by (tenant_id, sha256) — uploading the same content twice updates
	// metadata instead of duplicating storage.
	var id string
	err = h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO compliance_evidence
		   (tenant_id, control_id, filename, content_type, size_bytes, sha256, uploaded_by, notes, blob)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (tenant_id, sha256) DO UPDATE SET
		   control_id = EXCLUDED.control_id,
		   filename   = EXCLUDED.filename,
		   notes      = EXCLUDED.notes,
		   uploaded_at = NOW()
		 RETURNING id`,
		tenantID, controlID, header.Filename, contentType, len(blob), hash,
		uploadedByPtr, notes, blob,
	).Scan(&id)
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	logAudit(r, h.DB, "EVIDENCE_UPLOAD",
		"compliance_evidence/"+id+":"+controlID+":"+header.Filename)

	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{
		"id":           id,
		"control_id":   controlID,
		"filename":     header.Filename,
		"content_type": contentType,
		"size_bytes":   len(blob),
		"sha256":       hash,
	})
}

// List handles GET /api/v1/compliance/evidence?control_id=
func (h *ComplianceEvidence) List(w http.ResponseWriter, r *http.Request) {
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

	controlFilter := strings.TrimSpace(r.URL.Query().Get("control_id"))
	var rows pgx.Rows
	var err error
	if controlFilter != "" {
		rows, err = h.DB.Pool().Query(r.Context(),
			`SELECT id, control_id, filename, content_type, size_bytes, sha256,
			        uploaded_by, uploaded_at, notes
			   FROM compliance_evidence
			  WHERE tenant_id = $1 AND control_id = $2
			  ORDER BY uploaded_at DESC LIMIT 500`,
			tenantID, controlFilter)
	} else {
		rows, err = h.DB.Pool().Query(r.Context(),
			`SELECT id, control_id, filename, content_type, size_bytes, sha256,
			        uploaded_by, uploaded_at, notes
			   FROM compliance_evidence
			  WHERE tenant_id = $1
			  ORDER BY uploaded_at DESC LIMIT 500`,
			tenantID)
	}
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type item struct {
		ID          string    `json:"id"`
		ControlID   string    `json:"control_id"`
		Filename    string    `json:"filename"`
		ContentType string    `json:"content_type"`
		SizeBytes   int       `json:"size_bytes"`
		SHA256      string    `json:"sha256"`
		UploadedBy  *string   `json:"uploaded_by,omitempty"`
		UploadedAt  time.Time `json:"uploaded_at"`
		Notes       string    `json:"notes,omitempty"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.ControlID, &it.Filename, &it.ContentType,
			&it.SizeBytes, &it.SHA256, &it.UploadedBy, &it.UploadedAt, &it.Notes); err == nil {
			out = append(out, it)
		}
	}
	jsonOK(w, map[string]any{"items": out, "total": len(out)})
}

// Download handles GET /api/v1/compliance/evidence/{id}
func (h *ComplianceEvidence) Download(w http.ResponseWriter, r *http.Request) {
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
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	var (
		filename, contentType, hash string
		blob                        []byte
	)
	// Tenant scope in WHERE prevents IDOR — even if attacker knows the id of
	// another tenant's evidence row, the query returns 0 rows.
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT filename, content_type, sha256, blob
		   FROM compliance_evidence
		  WHERE id = $1 AND tenant_id = $2`,
		id, tenantID,
	).Scan(&filename, &contentType, &hash, &blob)
	if err != nil {
		jsonError(w, "evidence not found", http.StatusNotFound)
		return
	}
	logAudit(r, h.DB, "EVIDENCE_DOWNLOAD", "compliance_evidence/"+id+":"+filename)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(filename)+`"`)
	w.Header().Set("X-Content-SHA256", hash)
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write(blob)
}

// Delete handles DELETE /api/v1/compliance/evidence/{id} — admin only.
func (h *ComplianceEvidence) Delete(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden — admin role required", http.StatusForbidden)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`DELETE FROM compliance_evidence WHERE id = $1 AND tenant_id = $2`,
		id, tenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "evidence not found", http.StatusNotFound)
		return
	}
	logAudit(r, h.DB, "EVIDENCE_DELETE", "compliance_evidence/"+id)
	w.WriteHeader(http.StatusNoContent)
}

// sanitizeFilename strips path separators + control chars so a malicious upload
// can't poison the Content-Disposition header.
func sanitizeFilename(name string) string {
	if name == "" {
		return "evidence"
	}
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == '"' || r == '\\' || r == '/' {
			return '_'
		}
		return r
	}, name)
	if len(clean) > 200 {
		clean = clean[:200]
	}
	return clean
}
