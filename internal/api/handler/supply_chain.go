package handler

import (
	"encoding/json"
	"net/http"
	"fmt"
	"encoding/pem"
	"crypto/x509"
	"crypto/rand"
	"crypto/ecdsa"
	"crypto/elliptic"
	"os"
	"strings"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// SupplyChain handles Sigstore/SLSA/VEX endpoints (migration 015).
type SupplyChain struct {
	DB *store.DB
}

// ─── GET /api/v1/supply-chain/kpis ─────────────────────────────────────────
type scKPIs struct {
	Sigs         int64  `json:"sigs"`
	Provenance   int64  `json:"prov"`
	VEX          int64  `json:"vex"`
	KeyName      string `json:"key_name"`
	KeyAlgorithm string `json:"key_algo"`
}

func (h *SupplyChain) KPIs(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	ctx := r.Context()
	pool := h.DB.Pool()
	out := scKPIs{}

	_ = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM supply_chain_signatures WHERE tenant_id=$1`,
		claims.TenantID).Scan(&out.Sigs)
	_ = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM slsa_provenance WHERE tenant_id=$1`,
		claims.TenantID).Scan(&out.Provenance)
	_ = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vex_statements WHERE tenant_id=$1`,
		claims.TenantID).Scan(&out.VEX)
	// FIX #3: tenant_id filter được enable sau khi migration 022 chạy xong
	// (ALTER TABLE signing_keys ADD COLUMN tenant_id UUID).
	// Hiện tại query không có tenant filter — signing_keys là shared global key,
	// chỉ có 1 key active tại 1 thời điểm nên không có cross-tenant leak thực tế.
	// TODO: uncomment filter sau migration 022:
	//   WHERE revoked=false AND (tenant_id=$1 OR tenant_id IS NULL)
	_ = pool.QueryRow(ctx,
		`SELECT key_id, algorithm FROM signing_keys
		 WHERE revoked=false
		 ORDER BY created_at DESC LIMIT 1`).Scan(&out.KeyName, &out.KeyAlgorithm)

	jsonOK(w, out)
}

// ─── GET /api/v1/supply-chain/signatures ──────────────────────────────────
type scSignatureRow struct {
	ID         string     `json:"id"`
	Artifact   string     `json:"artifact"`
	Digest     string     `json:"digest"`
	SignedBy   string     `json:"signed_by"`
	Algorithm  string     `json:"algorithm"`
	SignedAt   time.Time  `json:"signed_at"`
	Verified   bool       `json:"verified"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	TlogIndex  *int64     `json:"tlog_index,omitempty"`
	HasCert    bool       `json:"has_cert"`
}

func (h *SupplyChain) Signatures(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	q := r.URL.Query()

	limit := queryInt(r, "limit", 100)
	if limit > 1000 {
		limit = 1000
	}
	offset := queryInt(r, "offset", 0)

	search := sanitizeString(q.Get("q"), 200)
	var searchPattern any
	if search != "" {
		searchPattern = "%" + search + "%"
	}

	// Single-literal SQL with nullable search bind — no string concat → no
	// taint-tracking false positive.
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id::text, artifact_name, artifact_digest, signed_by, algorithm,
		        signed_at, verified, verified_at, tlog_index,
		        (cert_pem IS NOT NULL AND cert_pem<>'')
		 FROM supply_chain_signatures
		 WHERE tenant_id = $1
		   AND ($2::text IS NULL
		        OR artifact_name   ILIKE $2
		        OR artifact_digest ILIKE $2
		        OR signed_by       ILIKE $2)
		 ORDER BY signed_at DESC
		 LIMIT $3 OFFSET $4`,
		claims.TenantID, searchPattern, limit, offset)
	if err != nil {
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []scSignatureRow{}
	for rows.Next() {
		var row scSignatureRow
		if err := rows.Scan(&row.ID, &row.Artifact, &row.Digest, &row.SignedBy,
			&row.Algorithm, &row.SignedAt, &row.Verified, &row.VerifiedAt,
			&row.TlogIndex, &row.HasCert); err != nil {
			continue
		}
		out = append(out, row)
	}

	var total int64
	totalArgs := []any{claims.TenantID}
	totalWhere := "tenant_id=$1"
	if search != "" {
		totalArgs = append(totalArgs, "%"+search+"%")
		totalWhere += " AND (artifact_name ILIKE $2 OR artifact_digest ILIKE $2 OR signed_by ILIKE $2)"
	}
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM supply_chain_signatures WHERE `+totalWhere,
		totalArgs...).Scan(&total)

	jsonOK(w, map[string]any{
		"signatures": out,
		"count":      total,
		"total":      total,
		"limit":      limit,
		"offset":     offset,
	})
}

// ─── GET /api/v1/supply-chain/signatures/{id} ──────────────────────────────
func (h *SupplyChain) SignatureDetail(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/supply-chain/signatures/")
	id = strings.TrimSuffix(id, "/")
	if id == "" || strings.Contains(id, "/") {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	var (
		row          scSignatureRow
		signatureB64 string
		publicKey    string
		certPEM      *string
		bundleJSON   []byte
	)
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT id::text, artifact_name, artifact_digest, signed_by, algorithm,
		        signed_at, verified, verified_at, tlog_index,
		        (cert_pem IS NOT NULL AND cert_pem<>''),
		        signature_b64, public_key_pem, cert_pem, bundle_json
		 FROM supply_chain_signatures
		 WHERE id=$1::uuid AND tenant_id=$2`,
		id, claims.TenantID).Scan(
		&row.ID, &row.Artifact, &row.Digest, &row.SignedBy, &row.Algorithm,
		&row.SignedAt, &row.Verified, &row.VerifiedAt, &row.TlogIndex,
		&row.HasCert, &signatureB64, &publicKey, &certPEM, &bundleJSON)
	if err != nil {
		jsonError(w, "signature not found", http.StatusNotFound)
		return
	}

	var bundle any
	_ = json.Unmarshal(bundleJSON, &bundle)

	jsonOK(w, map[string]any{
		"signature":     row,
		"signature_b64": signatureB64,
		"public_key":    publicKey,
		"cert_pem":      certPEM,
		"bundle":        bundle,
	})
}

// ─── POST /api/v1/supply-chain/signatures/{id}/verify ──────────────────────
func (h *SupplyChain) Verify(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/supply-chain/signatures/")
	path = strings.TrimSuffix(path, "/verify")
	id := strings.TrimSuffix(path, "/")
	if id == "" || strings.Contains(id, "/") {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	// Mark verified=true with current timestamp.
	// (Real Cosign verification would call cosign.VerifyBundle here;
	// for now we trust the recorded bundle and mark it verified.)
	tag, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE supply_chain_signatures
		 SET verified=true, verified_at=NOW()
		 WHERE id=$1::uuid AND tenant_id=$2`,
		id, claims.TenantID)
	if err != nil || tag.RowsAffected() == 0 {
		jsonError(w, "signature not found", http.StatusNotFound)
		return
	}

	// FIX #2: crypto_verified=false — DB-only mark, chưa gọi cosign.VerifyBundle() thật.
	// TODO: implement cosign.VerifyBundle() trước UPDATE, trả 422 nếu fail.
	jsonOK(w, map[string]any{
		"id":              id,
		"verified":        true,
		"crypto_verified": false,
		"warning":         "DB-only mark; cryptographic verification not yet implemented",
		"verified_at":     time.Now().UTC().Format(time.RFC3339),
		"trust_chain": []map[string]string{
			{"step": "Sigstore Root CA", "status": "pending"},
			{"step": "Fulcio Intermediate", "status": "pending"},
			{"step": "Artifact signature", "status": "pending"},
		},
	})
}

// ─── POST /api/v1/supply-chain/sign ────────────────────────────────────────
type signRequest struct {
	Artifact string `json:"artifact"`
	Digest   string `json:"digest"`
}

func (h *SupplyChain) Sign(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req signRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Artifact = strings.TrimSpace(req.Artifact)
	req.Digest = strings.TrimSpace(req.Digest)
	if req.Artifact == "" || req.Digest == "" {
		jsonError(w, "artifact and digest required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(req.Digest, "sha256:") {
		jsonError(w, "digest must start with sha256:", http.StatusBadRequest)
		return
	}

	// FIX #1: đọc private_key_enc (pgcrypto encrypted) thay vì private_key_pem plaintext.
	// Decrypt bằng VSP_KEY_PASSPHRASE từ env — không expose private key ra ngoài.
	passphrase := os.Getenv("VSP_KEY_PASSPHRASE")
	if passphrase == "" {
		jsonError(w, "signing key passphrase not configured", http.StatusServiceUnavailable)
		return
	}
	var keyID, pubKey string
	var privKeyEnc []byte
	if err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT key_id, public_key_pem, private_key_enc FROM signing_keys
		 WHERE revoked=false AND key_material_src='db_encrypted'
		 ORDER BY created_at DESC LIMIT 1`).Scan(&keyID, &pubKey, &privKeyEnc); err != nil {
		jsonError(w, "no active signing key", http.StatusServiceUnavailable)
		return
	}
	// Decrypt với pgcrypto — dùng DB function để tránh passphrase ở Go memory quá lâu
	var privKeyPEM string
	if err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT pgp_sym_decrypt($1, $2)`, privKeyEnc, passphrase).Scan(&privKeyPEM); err != nil {
		jsonInternalError(w, r, "key decryption failed", err)
		return
	}

	// FIX #5: dùng crypto/ecdsa thật thay placeholder string.
	sigB64, err := signDigestECDSA(privKeyPEM, req.Digest)
	if err != nil {
		jsonInternalError(w, r, "signing failed", err)
		return
	}
	bundle := map[string]any{
		"base64Signature": sigB64,
		"cert":            nil,
		"rekorBundle":     nil,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}
	bundleJSON, _ := json.Marshal(bundle)

	var newID string
	err = h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO supply_chain_signatures
		   (tenant_id, artifact_name, artifact_digest, signature_bytes, signature_b64,
		    public_key_pem, bundle_json, signed_by, algorithm, verified)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,false) -- FIX #5: false until Rekor verification
		 RETURNING id::text`,
		claims.TenantID, req.Artifact, req.Digest,
		[]byte(sigB64), sigB64, pubKey, bundleJSON, claims.Email,
		"ECDSA_P256_SHA256").Scan(&newID)
	if err != nil {
		jsonInternalError(w, r, "insert failed", err)
		return
	}

	jsonOK(w, map[string]any{
		"id":            newID,
		"artifact":      req.Artifact,
		"digest":        req.Digest,
		"signature_b64": sigB64,
		"key_id":        keyID,
		"verified":      false,
		"bundle":        bundle,
	})
}

// ─── GET /api/v1/supply-chain/provenance ───────────────────────────────────
type slsaRow struct {
	ID           string    `json:"id"`
	Artifact     string    `json:"artifact"`
	Digest       string    `json:"digest"`
	SLSALevel    int       `json:"slsa_level"`
	BuilderID    string    `json:"builder_id"`
	BuildType    string    `json:"build_type"`
	SourceURI    string    `json:"source_uri"`
	SourceCommit string    `json:"source_commit"`
	CreatedAt    time.Time `json:"created_at"`
}

func (h *SupplyChain) Provenance(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit := queryInt(r, "limit", 100)
	if limit > 1000 {
		limit = 1000
	}

	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id::text, artifact_name, artifact_digest, slsa_level, builder_id,
		        build_type, COALESCE(source_uri,''), COALESCE(source_commit,''), created_at
		 FROM slsa_provenance WHERE tenant_id=$1
		 ORDER BY created_at DESC LIMIT $2`,
		claims.TenantID, limit)
	if err != nil {
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []slsaRow{}
	for rows.Next() {
		var p slsaRow
		if err := rows.Scan(&p.ID, &p.Artifact, &p.Digest, &p.SLSALevel,
			&p.BuilderID, &p.BuildType, &p.SourceURI, &p.SourceCommit,
			&p.CreatedAt); err == nil {
			out = append(out, p)
		}
	}
	// FIX #4: bỏ fallback — nếu DB trả 0 thì total = 0, không che giấu empty state.
	var total int64
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM slsa_provenance WHERE tenant_id = $1`,
		claims.TenantID).Scan(&total)
	jsonOK(w, map[string]any{
		"provenance": out,
		"total":      total,
		"count":      total,
		"page_size":  len(out),
	})
}

// ─── POST /api/v1/supply-chain/provenance ──────────────────────────────────
type provReq struct {
	Artifact     string `json:"artifact"`
	Digest       string `json:"digest"`
	BuilderID    string `json:"builder_id"`
	SLSALevel    int    `json:"slsa_level"`
	SourceURI    string `json:"source_uri"`
	SourceCommit string `json:"source_commit"`
}

func (h *SupplyChain) GenerateProvenance(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req provReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Artifact == "" || req.Digest == "" || req.BuilderID == "" {
		jsonError(w, "artifact/digest/builder_id required", http.StatusBadRequest)
		return
	}
	if req.SLSALevel < 1 || req.SLSALevel > 4 {
		req.SLSALevel = 2
	}

	// Build in-toto-style statement
	statement := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]any{{
			"name":   req.Artifact,
			"digest": map[string]string{"sha256": strings.TrimPrefix(req.Digest, "sha256:")},
		}},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType":          "https://slsa-framework.github.io/slsa-github-generator",
				"externalParameters": map[string]any{"source_uri": req.SourceURI},
				"resolvedDependencies": []map[string]any{{
					"uri": req.SourceURI, "digest": map[string]string{"gitCommit": req.SourceCommit},
				}},
			},
			"runDetails": map[string]any{
				"builder":  map[string]string{"id": req.BuilderID},
				"metadata": map[string]any{"invocationId": time.Now().UnixNano()},
			},
		},
	}
	stmtJSON, _ := json.Marshal(statement)
	invJSON, _ := json.Marshal(map[string]any{"builder_id": req.BuilderID, "ts": time.Now()})
	matJSON, _ := json.Marshal([]map[string]any{{"uri": req.SourceURI, "commit": req.SourceCommit}})
	metaJSON, _ := json.Marshal(map[string]any{"reproducible": false, "buildStartedOn": time.Now()})

	var newID string
	err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO slsa_provenance
		   (tenant_id, artifact_name, artifact_digest, slsa_level, builder_id,
		    build_type, source_uri, source_commit, invocation_json,
		    materials_json, metadata_json, statement_json)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 RETURNING id::text`,
		claims.TenantID, req.Artifact, req.Digest, req.SLSALevel, req.BuilderID,
		"https://slsa-framework.github.io/slsa-github-generator", req.SourceURI,
		req.SourceCommit, invJSON, matJSON, metaJSON, stmtJSON).Scan(&newID)
	if err != nil {
		jsonInternalError(w, r, "insert failed", err)
		return
	}

	jsonOK(w, map[string]any{
		"id":         newID,
		"slsa_level": req.SLSALevel,
		"statement":  statement,
	})
}

// ─── GET /api/v1/supply-chain/vex ──────────────────────────────────────────
type vexRow struct {
	ID            string    `json:"id"`
	Product       string    `json:"product"`
	Version       string    `json:"version"`
	Component     string    `json:"component"`
	CompVersion   string    `json:"component_version,omitempty"`
	CVE           string    `json:"cve_id,omitempty"`
	Status        string    `json:"status"`
	Justification string    `json:"justification,omitempty"`
	Detail        string    `json:"detail,omitempty"`
	Author        string    `json:"author"`
	AnalysisDate  time.Time `json:"analysis_date"`
}

func (h *SupplyChain) VEX(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit := queryInt(r, "limit", 100)
	if limit > 1000 {
		limit = 1000
	}
	var statusFilter any
	if s := r.URL.Query().Get("status"); s != "" {
		statusFilter = s
	}

	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id::text, product_name, product_version, component_name,
		        COALESCE(component_version,''), COALESCE(cve_id,''), status,
		        COALESCE(justification,''), COALESCE(detail,''), author, analysis_date
		 FROM vex_statements
		 WHERE tenant_id = $1
		   AND ($2::text IS NULL OR status = $2)
		 ORDER BY analysis_date DESC
		 LIMIT $3`,
		claims.TenantID, statusFilter, limit)
	if err != nil {
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []vexRow{}
	for rows.Next() {
		var v vexRow
		if err := rows.Scan(&v.ID, &v.Product, &v.Version, &v.Component,
			&v.CompVersion, &v.CVE, &v.Status, &v.Justification, &v.Detail,
			&v.Author, &v.AnalysisDate); err == nil {
			out = append(out, v)
		}
	}
	// FIX #4: bỏ fallback — nếu DB trả 0 thì total = 0, không che giấu empty state.
	var total int64
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM vex_statements
		 WHERE tenant_id = $1
		   AND ($2::text IS NULL OR status = $2)`,
		claims.TenantID, statusFilter).Scan(&total)
	jsonOK(w, map[string]any{
		"vex":       out,
		"total":     total,
		"count":     total,
		"page_size": len(out),
	})
}

// ─── GET /api/v1/supply-chain/key ──────────────────────────────────────────
func (h *SupplyChain) Key(w http.ResponseWriter, r *http.Request) {
	var keyID, algo, pubPEM string
	var createdAt time.Time
	var expiresAt *time.Time
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT key_id, algorithm, public_key_pem, created_at, expires_at
		 FROM signing_keys WHERE revoked=false
		 ORDER BY created_at DESC LIMIT 1`).
		Scan(&keyID, &algo, &pubPEM, &createdAt, &expiresAt)
	if err != nil {
		jsonError(w, "no active signing key", http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]any{
		"key_id":         keyID,
		"algorithm":      algo,
		"public_key":     pubPEM,
		"public_key_pem": pubPEM,
		"created_at":     createdAt,
		"expires_at":     expiresAt,
	})
}

// ─── POST /api/v1/supply-chain/verify (verify a signed bundle) ─────────────
type verifyBundleReq struct {
	Bundle map[string]any `json:"bundle"`
}

func (h *SupplyChain) VerifyBundle(w http.ResponseWriter, r *http.Request) {
	var req verifyBundleReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Bundle == nil {
		jsonError(w, "bundle required", http.StatusBadRequest)
		return
	}

	// Extract signature/payload from bundle for echo
	sigB64, _ := req.Bundle["base64Signature"].(string)
	if sigB64 == "" {
		// Try alternate field names
		sigB64, _ = req.Bundle["signature"].(string)
	}

	// Get active signing key info for response
	var keyAlgo string
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT algorithm FROM signing_keys WHERE revoked=false
		 ORDER BY created_at DESC LIMIT 1`).Scan(&keyAlgo)

	if sigB64 == "" {
		jsonOK(w, map[string]any{
			"valid":     false,
			"error":     "no signature in bundle",
			"algorithm": keyAlgo,
		})
		return
	}

	// In production, this would call cosign.VerifyBundle.
	// For now: accept bundle as valid if it has the expected fields.
	// FIX #2: crypto_verified=false — structural check only, chưa verify thật.
	jsonOK(w, map[string]any{
		"valid":           true,
		"crypto_verified": false,
		"warning":         "structural check only; cryptographic verification not yet implemented",
		"algorithm":       keyAlgo,
		"payload":         req.Bundle,
		"trust_chain": []map[string]string{
			{"step": "Sigstore Root CA", "status": "pending"},
			{"step": "Fulcio Intermediate", "status": "pending"},
			{"step": "Bundle signature", "status": "pending"},
		},
	})
}

// ─── DELETE /api/v1/supply-chain/signatures/{id} ── FIX #7 ─────────────────
func (h *SupplyChain) DeleteSignature(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/supply-chain/signatures/")
	id = strings.TrimSuffix(id, "/")
	if id == "" || strings.Contains(id, "/") {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`DELETE FROM supply_chain_signatures WHERE id=$1::uuid AND tenant_id=$2`,
		id, claims.TenantID)
	if err != nil {
		jsonInternalError(w, r, "delete failed", err)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "signature not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── DELETE /api/v1/supply-chain/provenance/{id} ── FIX #7 ─────────────────
func (h *SupplyChain) DeleteProvenance(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/supply-chain/provenance/")
	id = strings.TrimSuffix(id, "/")
	if id == "" || strings.Contains(id, "/") {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`DELETE FROM slsa_provenance WHERE id=$1::uuid AND tenant_id=$2`,
		id, claims.TenantID)
	if err != nil {
		jsonInternalError(w, r, "delete failed", err)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "provenance not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── POST /api/v1/supply-chain/vex ── FIX #7 ───────────────────────────────
type vexCreateReq struct {
	Product       string `json:"product"`
	Version       string `json:"version"`
	Component     string `json:"component"`
	CompVersion   string `json:"component_version"`
	CVE           string `json:"cve_id"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
	Detail        string `json:"detail"`
}

var validVexStatuses = map[string]bool{
	"not_affected": true, "affected": true,
	"fixed": true, "under_investigation": true,
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func (h *SupplyChain) CreateVEX(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req vexCreateReq
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Product = strings.TrimSpace(req.Product)
	req.Component = strings.TrimSpace(req.Component)
	if req.Product == "" || req.Component == "" {
		jsonError(w, "product and component required", http.StatusBadRequest)
		return
	}
	if !validVexStatuses[req.Status] {
		req.Status = "under_investigation"
	}
	// Build statement_json (VEX CSAF-style minimal statement)
	stmtJSON, _ := json.Marshal(map[string]any{
		"product":       req.Product,
		"version":       req.Version,
		"component":     req.Component,
		"cve_id":        req.CVE,
		"status":        req.Status,
		"justification": req.Justification,
		"detail":        req.Detail,
		"author":        claims.Email,
	})
	var newID string
	if err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO vex_statements
		   (tenant_id, product_name, product_version, component_name, component_version,
		    cve_id, status, justification, detail, author, analysis_date, statement_json)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),$11)
		 RETURNING id::text`,
		claims.TenantID, req.Product, req.Version, req.Component, nullIfEmpty(req.CompVersion),
		nullIfEmpty(req.CVE), req.Status, nullIfEmpty(req.Justification),
		nullIfEmpty(req.Detail), claims.Email, stmtJSON).Scan(&newID); err != nil {
		jsonInternalError(w, r, "insert failed", err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": newID, "status": req.Status})
}

// ─── PATCH /api/v1/supply-chain/vex/{id} ── FIX #7 ─────────────────────────
type vexPatchReq struct {
	Status        string `json:"status"`
	Justification string `json:"justification"`
	Detail        string `json:"detail"`
}

func (h *SupplyChain) PatchVEX(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/supply-chain/vex/")
	id = strings.TrimSuffix(id, "/")
	if id == "" || strings.Contains(id, "/") {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req vexPatchReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Status != "" && !validVexStatuses[req.Status] {
		jsonError(w, "invalid status; valid: not_affected, affected, fixed, under_investigation", http.StatusBadRequest)
		return
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE vex_statements SET
		   status        = COALESCE(NULLIF($3,''), status),
		   justification = COALESCE(NULLIF($4,''), justification),
		   detail        = COALESCE(NULLIF($5,''), detail),
		   analysis_date = NOW()
		 WHERE id=$1::uuid AND tenant_id=$2`,
		id, claims.TenantID, req.Status, req.Justification, req.Detail)
	if err != nil {
		jsonInternalError(w, r, "update failed", err)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "vex statement not found", http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]any{"id": id, "updated": true})
}

// ─── DELETE /api/v1/supply-chain/vex/{id} ── FIX #7 ────────────────────────
func (h *SupplyChain) DeleteVEX(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/supply-chain/vex/")
	id = strings.TrimSuffix(id, "/")
	if id == "" || strings.Contains(id, "/") {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`DELETE FROM vex_statements WHERE id=$1::uuid AND tenant_id=$2`,
		id, claims.TenantID)
	if err != nil {
		jsonInternalError(w, r, "delete failed", err)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "vex statement not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── POST /api/v1/supply-chain/key/rotate ── IMPROVEMENT ───────────────────
// Tạo ECDSA P-256 key mới, revoke key cũ, encrypt + lưu vào DB.
// Chỉ admin mới được gọi endpoint này.
func (h *SupplyChain) RotateKey(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if claims.Role != "admin" {
		jsonError(w, "admin role required for key rotation", http.StatusForbidden)
		return
	}

	passphrase := os.Getenv("VSP_KEY_PASSPHRASE")
	if passphrase == "" {
		jsonError(w, "VSP_KEY_PASSPHRASE not configured", http.StatusServiceUnavailable)
		return
	}

	// Generate new ECDSA P-256 key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		jsonInternalError(w, r, "key generation failed", err)
		return
	}

	// Encode private key → PEM
	privDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		jsonInternalError(w, r, "marshal private key failed", err)
		return
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))

	// Encode public key → PEM
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		jsonInternalError(w, r, "marshal public key failed", err)
		return
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	keyID := fmt.Sprintf("vsp-signing-%d", time.Now().Unix())

	// Encrypt private key với pgcrypto trong DB transaction
	tx, err := h.DB.Pool().Begin(r.Context())
	if err != nil {
		jsonInternalError(w, r, "begin transaction failed", err)
		return
	}
	defer tx.Rollback(r.Context())

	// Revoke tất cả key cũ
	if _, err := tx.Exec(r.Context(),
		`UPDATE signing_keys SET revoked=true, revoked_at=NOW() WHERE revoked=false`); err != nil {
		jsonInternalError(w, r, "revoke old keys failed", err)
		return
	}

	// Insert key mới với encrypted private key
	var newID string
	if err := tx.QueryRow(r.Context(),
		`INSERT INTO signing_keys
		   (key_id, algorithm, public_key_pem, private_key_enc, key_material_src, usage)
		 VALUES ($1, $2, $3, pgp_sym_encrypt($4, $5), 'db_encrypted', 'artifact_signing')
		 RETURNING id::text`,
		keyID, "ECDSA_P256", pubPEM, privPEM, passphrase).Scan(&newID); err != nil {
		jsonInternalError(w, r, "insert new key failed", err)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		jsonInternalError(w, r, "commit failed", err)
		return
	}

	jsonOK(w, map[string]any{
		"id":         newID,
		"key_id":     keyID,
		"algorithm":  "ECDSA_P256",
		"public_key": pubPEM,
		"rotated_at": time.Now().UTC().Format(time.RFC3339),
		"message":    "key rotated successfully; old keys revoked",
	})
}

// ─── GET /api/v1/supply-chain/stats ── IMPROVEMENT ─────────────────────────
// Chart data: signatures per day (30 ngày), VEX by status, SLSA level dist.
func (h *SupplyChain) Stats(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	ctx := r.Context()

	// Signatures per day — 30 ngày gần nhất
	sigRows, err := h.DB.Pool().Query(ctx,
		`SELECT DATE(signed_at)::text as day, COUNT(*) as cnt
		 FROM supply_chain_signatures
		 WHERE tenant_id=$1 AND signed_at >= NOW() - INTERVAL '30 days'
		 GROUP BY DATE(signed_at)
		 ORDER BY day ASC`,
		claims.TenantID)
	sigPerDay := []map[string]any{}
	if err == nil {
		defer sigRows.Close()
		for sigRows.Next() {
			var day string
			var cnt int64
			if sigRows.Scan(&day, &cnt) == nil {
				sigPerDay = append(sigPerDay, map[string]any{"day": day, "count": cnt})
			}
		}
	}

	// VEX by status
	vexRows, err := h.DB.Pool().Query(ctx,
		`SELECT status, COUNT(*) as cnt FROM vex_statements
		 WHERE tenant_id=$1 GROUP BY status ORDER BY cnt DESC`,
		claims.TenantID)
	vexByStatus := []map[string]any{}
	if err == nil {
		defer vexRows.Close()
		for vexRows.Next() {
			var status string
			var cnt int64
			if vexRows.Scan(&status, &cnt) == nil {
				vexByStatus = append(vexByStatus, map[string]any{"status": status, "count": cnt})
			}
		}
	}

	// SLSA level distribution
	slsaRows, err := h.DB.Pool().Query(ctx,
		`SELECT slsa_level, COUNT(*) as cnt FROM slsa_provenance
		 WHERE tenant_id=$1 GROUP BY slsa_level ORDER BY slsa_level ASC`,
		claims.TenantID)
	slsaDist := []map[string]any{}
	if err == nil {
		defer slsaRows.Close()
		for slsaRows.Next() {
			var level int
			var cnt int64
			if slsaRows.Scan(&level, &cnt) == nil {
				slsaDist = append(slsaDist, map[string]any{"level": level, "count": cnt})
			}
		}
	}

	// Verified vs unverified ratio
	var verified, unverified int64
	_ = h.DB.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FILTER (WHERE verified=true),
		        COUNT(*) FILTER (WHERE verified=false)
		 FROM supply_chain_signatures WHERE tenant_id=$1`,
		claims.TenantID).Scan(&verified, &unverified)

	// Key expiry warning
	var expiresAt *time.Time
	var keyID string
	_ = h.DB.Pool().QueryRow(ctx,
		`SELECT key_id, expires_at FROM signing_keys
		 WHERE revoked=false ORDER BY created_at DESC LIMIT 1`).
		Scan(&keyID, &expiresAt)

	keyWarning := ""
	if expiresAt != nil {
		days := int(time.Until(*expiresAt).Hours() / 24)
		if days < 0 {
			keyWarning = "EXPIRED"
		} else if days < 30 {
			keyWarning = fmt.Sprintf("expires in %d days", days)
		}
	}

	jsonOK(w, map[string]any{
		"signatures_per_day": sigPerDay,
		"vex_by_status":      vexByStatus,
		"slsa_distribution":  slsaDist,
		"verified_ratio": map[string]any{
			"verified":   verified,
			"unverified": unverified,
			"total":      verified + unverified,
		},
		"key_warning": keyWarning,
		"key_id":      keyID,
	})
}

// ─── GET /api/v1/supply-chain/sbom ── IMPROVEMENT ──────────────────────────
// SBOM endpoint stub — trả danh sách SBOMs từ sw_inventory hoặc sbom table.
// Đây là bridge giữa supply chain tab và SBOM tab.
type sbomRow struct {
	ID        string    `json:"id"`
	Artifact  string    `json:"artifact"`
	Format    string    `json:"format"`
	Version   string    `json:"version"`
	Component int       `json:"component_count"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *SupplyChain) SBOM(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit := queryInt(r, "limit", 50)
	if limit > 500 {
		limit = 500
	}

	// Query từ sbom_documents table nếu tồn tại, fallback trả empty
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id::text, COALESCE(artifact_name,''), COALESCE(format,'cyclonedx'),
		        COALESCE(spec_version,'1.4'), COALESCE(component_count,0), created_at
		 FROM sbom_documents
		 WHERE tenant_id=$1
		 ORDER BY created_at DESC LIMIT $2`,
		claims.TenantID, limit)

	out := []sbomRow{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s sbomRow
			if rows.Scan(&s.ID, &s.Artifact, &s.Format, &s.Version, &s.Component, &s.CreatedAt) == nil {
				out = append(out, s)
			}
		}
	}
	// err != nil nghĩa là table chưa tồn tại — trả empty list, không trả 500
	jsonOK(w, map[string]any{
		"sboms": out,
		"total": len(out),
	})
}
