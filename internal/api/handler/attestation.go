package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// CISAAttestation handles CISA Secure Software Self-Attestation Common Form
// + NIST SP 800-218 SSDF practices (migration 016).
type CISAAttestation struct {
	DB *store.DB
}

// ─── GET /api/v1/cisa-attestation/kpis ─────────────────────────────────────
type attKPIs struct {
	Attestable int `json:"attestable"`
	Total      int `json:"total"`
	Pct        int `json:"pct"`
	Forms      int `json:"forms"`
	Signed     int `json:"signed"`
}

func (h *CISAAttestation) KPIs(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	ctx := r.Context()
	pool := h.DB.Pool()
	out := attKPIs{}

	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM ssdf_practices`).Scan(&out.Total)
	_ = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM ssdf_practices WHERE status IN ('implemented','partial')`).
		Scan(&out.Attestable)
	if out.Total > 0 {
		out.Pct = (out.Attestable * 100) / out.Total
	}
	_ = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM attestation_forms WHERE tenant_id=$1`,
		claims.TenantID).Scan(&out.Forms)
	_ = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM attestation_forms WHERE tenant_id=$1 AND status='signed'`,
		claims.TenantID).Scan(&out.Signed)

	jsonOK(w, out)
}

// ─── GET /api/v1/cisa-attestation/practices ────────────────────────────────
type ssdfRow struct {
	ID                  string          `json:"practice_id"`
	GroupCode           string          `json:"group_code"`
	Name                string          `json:"name"`
	Description         string          `json:"description"`
	Status              string          `json:"status"`
	EvidenceRefs        json.RawMessage `json:"evidence_refs"`
	ImplementationNotes string          `json:"implementation_notes"`
	ResponsibleRole     string          `json:"responsible_role"`
	LastAssessed        time.Time       `json:"last_assessed"`
}

func (h *CISAAttestation) Practices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	statusFilter := q.Get("status")
	groupFilter := q.Get("group")

	args := []any{}
	where := "1=1"
	if statusFilter != "" {
		args = append(args, statusFilter)
		where += " AND status=$1"
	}
	if groupFilter != "" {
		args = append(args, groupFilter)
		idx := len(args)
		where += " AND group_code=$" + strconv.Itoa(idx)
	}

	// where is literal SQL with $N placeholders; user input via args.
	rows, err := h.DB.Pool().Query(r.Context(),
		// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
		`SELECT practice_id, group_code, name, COALESCE(description,''), status,
		        COALESCE(evidence_refs,'[]'::jsonb), COALESCE(implementation_notes,''),
		        COALESCE(responsible_role,''), COALESCE(last_assessed, NOW())
		 FROM ssdf_practices WHERE `+where+`
		 ORDER BY group_code, practice_id`,
		args...)
	if err != nil {
		log.Warn().Err(err).Msg("attestation: practices query failed")
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []ssdfRow{}
	for rows.Next() {
		var s ssdfRow
		var refs []byte
		if err := rows.Scan(&s.ID, &s.GroupCode, &s.Name, &s.Description, &s.Status,
			&refs, &s.ImplementationNotes, &s.ResponsibleRole, &s.LastAssessed); err == nil {
			s.EvidenceRefs = refs
			out = append(out, s)
		}
	}

	// Group counts for UI
	counts := map[string]int{"implemented": 0, "partial": 0, "not_implemented": 0, "not_applicable": 0}
	for _, p := range out {
		counts[p.Status]++
	}

	jsonOK(w, map[string]any{
		"practices": out,
		"total":     len(out),
		"counts":    counts,
	})
}

// ─── POST /api/v1/cisa-attestation/practices/{id} ──────────────────────────
type practiceUpdate struct {
	Status              string          `json:"status"`
	ImplementationNotes string          `json:"implementation_notes"`
	EvidenceRefs        json.RawMessage `json:"evidence_refs"`
}

func (h *CISAAttestation) UpdatePractice(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/cisa-attestation/practices/")
	id = strings.TrimSuffix(id, "/")
	if id == "" || strings.Contains(id, "/") {
		jsonError(w, "invalid practice_id", http.StatusBadRequest)
		return
	}

	var req practiceUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Status != "" {
		valid := map[string]bool{"not_implemented": true, "partial": true, "implemented": true, "not_applicable": true}
		if !valid[req.Status] {
			jsonError(w, "invalid status", http.StatusBadRequest)
			return
		}
	}

	if len(req.EvidenceRefs) == 0 {
		req.EvidenceRefs = json.RawMessage(`[]`)
	}

	tag, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE ssdf_practices
		 SET status = COALESCE(NULLIF($1,''), status),
		     implementation_notes = COALESCE(NULLIF($2,''), implementation_notes),
		     evidence_refs = COALESCE($3::jsonb, evidence_refs),
		     updated_at = NOW(),
		     last_assessed = NOW()
		 WHERE practice_id=$4`,
		req.Status, req.ImplementationNotes, req.EvidenceRefs, id)
	if err != nil {
		log.Warn().Err(err).Msg("attestation: practice update failed")
		jsonError(w, "update failed", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "practice not found", http.StatusNotFound)
		return
	}
	logAudit(r, h.DB, "ATTEST_PRACTICE_UPDATED", "cisa_attestation/practices")
	jsonOK(w, map[string]any{"practice_id": id, "updated": true})
}

// ─── GET /api/v1/cisa-attestation/forms ────────────────────────────────────
type formRow struct {
	FormUUID       string     `json:"form_uuid"`
	ProductName    string     `json:"product_name"`
	ProductVersion string     `json:"product_version"`
	Status         string     `json:"status"`
	SignedByName   string     `json:"signed_by_name,omitempty"`
	SignedAt       *time.Time `json:"signed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (h *CISAAttestation) Forms(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	q := r.URL.Query()
	limit := queryInt(r, "limit", 100)
	if limit > 500 {
		limit = 500
	}
	offset := queryInt(r, "offset", 0)
	statusFilter := q.Get("status")

	args := []any{claims.TenantID}
	where := "tenant_id=$1"
	if statusFilter != "" {
		args = append(args, statusFilter)
		where += " AND status=$2"
	}
	args = append(args, limit, offset)

	// where + LIMIT/OFFSET are literal SQL with $N placeholders; user input via args.
	rows, err := h.DB.Pool().Query(r.Context(),
		// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
		`SELECT form_uuid, product_name, product_version, status,
		        COALESCE(signed_by_name,''), signature_date, created_at, updated_at
		 FROM attestation_forms WHERE `+where+`
		 ORDER BY updated_at DESC
		 LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		log.Warn().Err(err).Msg("attestation: forms query failed")
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []formRow{}
	for rows.Next() {
		var f formRow
		if err := rows.Scan(&f.FormUUID, &f.ProductName, &f.ProductVersion,
			&f.Status, &f.SignedByName, &f.SignedAt, &f.CreatedAt, &f.UpdatedAt); err == nil {
			out = append(out, f)
		}
	}

	var total, signed int
	totalArgs := []any{claims.TenantID}
	totalWhere := "tenant_id=$1"
	if statusFilter != "" {
		totalArgs = append(totalArgs, statusFilter)
		totalWhere += " AND status=$2"
	}
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*), SUM(CASE WHEN status='signed' THEN 1 ELSE 0 END)
		 FROM attestation_forms WHERE `+totalWhere,
		totalArgs...).Scan(&total, &signed)

	jsonOK(w, map[string]any{
		"forms":  out,
		"total":  total,
		"signed": signed,
		"limit":  limit,
		"offset": offset,
	})
}

// ─── GET /api/v1/cisa-attestation/forms/{uuid} ─────────────────────────────
func (h *CISAAttestation) FormDetail(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	uuidStr := strings.TrimPrefix(r.URL.Path, "/api/v1/cisa-attestation/forms/")
	uuidStr = strings.TrimSuffix(uuidStr, "/")
	if uuidStr == "" || strings.Contains(uuidStr, "/") {
		jsonError(w, "invalid form_uuid", http.StatusBadRequest)
		return
	}

	var f formRow
	var producerName, producerWebsite, productDesc string
	var signedByTitle, signedByEmail, sigMethod string
	var ssdfJSON []byte
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT form_uuid, producer_name, COALESCE(producer_website,''), product_name,
		        product_version, COALESCE(product_description,''),
		        ssdf_attestations, COALESCE(signed_by_name,''),
		        COALESCE(signed_by_title,''), COALESCE(signed_by_email,''),
		        signature_date, COALESCE(signature_method,''),
		        status, created_at, updated_at
		 FROM attestation_forms
		 WHERE form_uuid=$1 AND tenant_id=$2`,
		uuidStr, claims.TenantID).Scan(
		&f.FormUUID, &producerName, &producerWebsite, &f.ProductName,
		&f.ProductVersion, &productDesc, &ssdfJSON, &f.SignedByName,
		&signedByTitle, &signedByEmail, &f.SignedAt, &sigMethod,
		&f.Status, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		jsonError(w, "form not found", http.StatusNotFound)
		return
	}
	var ssdfAttestations any
	_ = json.Unmarshal(ssdfJSON, &ssdfAttestations)

	jsonOK(w, map[string]any{
		"form":                f,
		"producer_name":       producerName,
		"producer_website":    producerWebsite,
		"product_description": productDesc,
		"ssdf_attestations":   ssdfAttestations,
		"signed_by_title":     signedByTitle,
		"signed_by_email":     signedByEmail,
		"signature_method":    sigMethod,
	})
}

// ─── POST /api/v1/cisa-attestation/forms (create new draft) ────────────────
type newFormReq struct {
	ProductName    string `json:"product_name"`
	ProductVersion string `json:"product_version"`
	ProducerName   string `json:"producer_name"`
}

func (h *CISAAttestation) GenerateDraft(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req newFormReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.ProductName == "" {
		req.ProductName = "VSP Security Platform"
	}
	if req.ProductVersion == "" {
		req.ProductVersion = "1.1"
	}
	if req.ProducerName == "" {
		req.ProducerName = "VSP Inc."
	}

	// Auto-snapshot current SSDF practice statuses
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT practice_id, status, COALESCE(implementation_notes,'')
		 FROM ssdf_practices`)
	if err != nil {
		jsonError(w, "snapshot query failed", http.StatusInternalServerError)
		return
	}
	snapshot := map[string]map[string]string{}
	for rows.Next() {
		var pid, status, notes string
		if err := rows.Scan(&pid, &status, &notes); err == nil {
			snapshot[pid] = map[string]string{"status": status, "notes": notes}
		}
	}
	rows.Close()
	snapshotJSON, _ := json.Marshal(snapshot)

	formUUID := uuid.New().String()

	var newID string
	err = h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO attestation_forms
		   (tenant_id, form_uuid, producer_name, product_name, product_version,
		    ssdf_attestations, status)
		 VALUES ($1,$2,$3,$4,$5,$6,'draft')
		 RETURNING id::text`,
		claims.TenantID, formUUID, req.ProducerName, req.ProductName,
		req.ProductVersion, snapshotJSON).Scan(&newID)
	if err != nil {
		jsonError(w, "insert failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	logAudit(r, h.DB, "ATTEST_DRAFT_GENERATED", "cisa_attestation/draft")
	jsonOK(w, map[string]any{
		"form_uuid":         formUUID,
		"id":                newID,
		"product_name":      req.ProductName,
		"product_version":   req.ProductVersion,
		"status":            "draft",
		"ssdf_attestations": snapshot,
	})
}

// ─── POST /api/v1/cisa-attestation/forms/{uuid}/sign ───────────────────────
type signFormReq struct {
	Name            string `json:"signed_by_name"`
	Title           string `json:"signed_by_title"`
	Email           string `json:"signed_by_email"`
	SignatureMethod string `json:"signature_method"`
}

func (h *CISAAttestation) SignForm(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/cisa-attestation/forms/")
	path = strings.TrimSuffix(path, "/sign")
	uuidStr := strings.TrimSuffix(path, "/")
	if uuidStr == "" || strings.Contains(uuidStr, "/") {
		jsonError(w, "invalid form_uuid", http.StatusBadRequest)
		return
	}

	var req signFormReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Title == "" || req.Email == "" {
		jsonError(w, "name, title and email required", http.StatusBadRequest)
		return
	}
	if req.SignatureMethod == "" {
		req.SignatureMethod = "electronic"
	}

	tag, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE attestation_forms
		 SET signed_by_name=$1, signed_by_title=$2, signed_by_email=$3,
		     signature_method=$4, signature_date=NOW(), status='signed',
		     updated_at=NOW()
		 WHERE form_uuid=$5 AND tenant_id=$6 AND status='draft'`,
		req.Name, req.Title, req.Email, req.SignatureMethod, uuidStr, claims.TenantID)
	if err != nil {
		log.Warn().Err(err).Msg("attestation: form sign failed")
		jsonError(w, "update failed", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "form not found or already signed", http.StatusNotFound)
		return
	}

	logAudit(r, h.DB, "ATTEST_FORM_SIGNED", "cisa_attestation/sign")
	jsonOK(w, map[string]any{
		"form_uuid":        uuidStr,
		"signed":           true,
		"signed_by_name":   req.Name,
		"signed_by_title":  req.Title,
		"signature_method": req.SignatureMethod,
		"signature_date":   time.Now().UTC().Format(time.RFC3339),
	})
}

// ─── GET /api/v1/cisa-attestation/draft (current draft) ────────────────────
func (h *CISAAttestation) CurrentDraft(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	var f formRow
	var ssdfJSON []byte
	var producerName string
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT form_uuid, producer_name, product_name, product_version,
		        ssdf_attestations, COALESCE(signed_by_name,''),
		        signature_date, status, created_at, updated_at
		 FROM attestation_forms
		 WHERE tenant_id=$1 AND status='draft'
		 ORDER BY updated_at DESC LIMIT 1`,
		claims.TenantID).Scan(
		&f.FormUUID, &producerName, &f.ProductName, &f.ProductVersion,
		&ssdfJSON, &f.SignedByName, &f.SignedAt, &f.Status, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		// No draft yet → return empty
		jsonOK(w, map[string]any{"form": nil})
		return
	}

	var ssdf any
	_ = json.Unmarshal(ssdfJSON, &ssdf)

	jsonOK(w, map[string]any{
		"form":              f,
		"producer_name":     producerName,
		"ssdf_attestations": ssdf,
	})
}

// ─── helpers ───────────────────────────────────────────────────────────────
// (uses strconv.Itoa via imported package — see attestation_helpers below)
