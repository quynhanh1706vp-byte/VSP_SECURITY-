package main

// run_provenance.go — SLSA L3 readiness: per-run signed provenance.
//
// Closes the L2→L3 gap by attaching cryptographic signatures to provenance
// statements. Existing handleGenProvenance writes statement_json without a
// detached signature (L2 ceiling — anyone with DB access can forge). This
// file adds:
//
//   POST /api/v1/runs/{rid}/provenance         — generate + sign + persist
//   GET  /api/v1/runs/{rid}/provenance         — return the DSSE envelope
//   GET  /api/v1/runs/{rid}/provenance/verify  — verify the stored signature
//
// L3 hardware-isolation requirement is satisfied at deployment time, not in
// code: the operator runs the binary with VSP_SECRETS_PROVIDER=vault and a
// signing key stored in Vault Transit / HSM. See docs/SLSA_L3_RUNBOOK.md.
//
// Output format: in-toto attestation v1 / DSSE envelope —
//   { "payloadType": "application/vnd.in-toto+json",
//     "payload": "<base64(statement_json)>",
//     "signatures": [{"keyid": "...", "sig": "<base64(ECDSA-P256-sig)>"}] }
// Compatible with cosign verify-attestation and Rekor witness submissions.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// ── canonicalisation ───────────────────────────────────────────────────────
//
// The payload we sign MUST be canonical: same bytes in → same hash out, on
// any platform. Go's encoding/json sorts struct fields by declaration order
// (not alpha) but is otherwise deterministic for the same input. For map
// fields we explicitly sort keys via json.Marshal's default behaviour
// (which is alpha for map keys). This is sufficient because no in-toto
// verifier we target requires JSON canonicalisation per RFC8785; they hash
// the bytes we actually send.

// dsseEnvelope is the attestation v1 envelope wire format.
type dsseEnvelope struct {
	PayloadType string                  `json:"payloadType"`
	Payload     string                  `json:"payload"` // base64(statement)
	Signatures  []dsseEnvelopeSignature `json:"signatures"`
}

type dsseEnvelopeSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64
}

// runProvenanceContext holds the data we pull from the runs row to build
// the in-toto statement. Kept tiny on purpose — avoid leaking finding
// content into provenance, which is a public artifact.
type runProvenanceContext struct {
	RunID        string
	RID          string
	TenantID     string
	Mode         string
	Profile      string
	Source       string
	Status       string
	StartedAt    time.Time
	FinishedAt   time.Time
	TotalFinding int
}

// loadRunForProvenance gathers the minimal run row needed to build a
// statement. Returns ErrNotFound semantics via sql.ErrNoRows.
func loadRunForProvenance(ctx context.Context, db *sql.DB, rid string) (*runProvenanceContext, error) {
	var c runProvenanceContext
	var startedAt, finishedAt sql.NullTime
	var src sql.NullString
	err := db.QueryRowContext(ctx, `
		SELECT id::text, rid, tenant_id::text, mode, profile,
		       COALESCE(src,''), status,
		       started_at, finished_at, COALESCE(total_findings, 0)
		  FROM runs
		 WHERE rid = $1 OR id::text = $1
		 LIMIT 1`, rid).Scan(
		&c.RunID, &c.RID, &c.TenantID, &c.Mode, &c.Profile,
		&src, &c.Status, &startedAt, &finishedAt, &c.TotalFinding,
	)
	if err != nil {
		return nil, err
	}
	if src.Valid {
		c.Source = src.String
	}
	if startedAt.Valid {
		c.StartedAt = startedAt.Time
	}
	if finishedAt.Valid {
		c.FinishedAt = finishedAt.Time
	}
	return &c, nil
}

// buildSignedProvenance constructs an in-toto Statement v1 + signs it,
// returning the canonical statement bytes and the DSSE envelope.
func buildSignedProvenance(c *runProvenanceContext) (statementBytes []byte, env *dsseEnvelope, err error) {
	subjectName := "vsp-scan-run/" + c.RID
	if c.Source != "" {
		subjectName = c.Source + "@" + c.RID
	}

	stmt := InTotoStatement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []InTotoSubject{{
			Name: subjectName,
			// We don't have an output artefact digest for a scan run, so we
			// hash the deterministic combination of (rid, tenant, finished_at)
			// as the subject digest. This binds the statement to a specific
			// run rather than to a build output.
			Digest: map[string]string{
				"sha256": digestHex(c.RID + ":" + c.TenantID + ":" + c.FinishedAt.UTC().Format(time.RFC3339Nano)),
			},
		}},
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: SLSAPredicate{
			BuildDefinition: SLSABuildDefinition{
				BuildType: "https://vsp.dev/buildtypes/scan-run/v1",
				ExternalParameters: map[string]any{
					"rid":     c.RID,
					"mode":    c.Mode,
					"profile": c.Profile,
					"source":  c.Source,
				},
				InternalParameters: map[string]any{
					"gateway_version": gatewayVersion(),
				},
			},
			RunDetails: SLSARunDetails{
				Builder: SLSABuilder{
					ID: "https://vsp.dev/builders/gateway/v1",
					Version: map[string]string{
						"gateway": gatewayVersion(),
					},
				},
				Metadata: SLSAMetadata{
					InvocationID: c.RunID,
					StartedOn:    c.StartedAt,
					FinishedOn:   c.FinishedAt,
					Reproducible: false, // L4 only; scans are not bitwise-reproducible
				},
			},
		},
	}
	statementBytes, err = json.Marshal(stmt)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal statement: %w", err)
	}
	sig, err := signBytes(statementBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("sign statement: %w", err)
	}
	env = &dsseEnvelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString(statementBytes),
		Signatures: []dsseEnvelopeSignature{{
			KeyID: signingKeyID,
			Sig:   base64.StdEncoding.EncodeToString(sig),
		}},
	}
	return statementBytes, env, nil
}

// HTTP — POST /api/v1/runs/{rid}/provenance
// Generates, signs, and persists provenance for the run. Idempotent: if
// provenance already exists for the run we return the existing envelope.
func handleRunProvenanceGenerate(w http.ResponseWriter, r *http.Request) {
	rid := strings.TrimSpace(chi.URLParam(r, "rid"))
	if rid == "" {
		writeJSONErr(w, http.StatusBadRequest, "rid required")
		return
	}
	if p4SQLDB == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "p4 db unavailable")
		return
	}
	ctx := r.Context()

	c, err := loadRunForProvenance(ctx, p4SQLDB, rid)
	if err == sql.ErrNoRows {
		writeJSONErr(w, http.StatusNotFound, "run not found")
		return
	}
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "load run: "+err.Error())
		return
	}
	if c.Status != "COMPLETED" {
		writeJSONErr(w, http.StatusConflict, "run not completed (status="+c.Status+")")
		return
	}

	// Idempotency — if a signed row exists for this run, return it.
	if existing := loadExistingProvenance(ctx, p4SQLDB, c.RunID); existing != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"already_signed": true,
			"key_id":         existing.Signatures[0].KeyID,
			"envelope":       existing,
		})
		return
	}

	stmtBytes, env, err := buildSignedProvenance(c)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	envJSON, _ := json.Marshal(env)

	if _, err := p4SQLDB.ExecContext(ctx, `
		INSERT INTO slsa_provenance
		  (tenant_id, artifact_name, artifact_digest, slsa_level, builder_id,
		   build_type, source_uri, source_commit, invocation_json,
		   materials_json, metadata_json, statement_json,
		   run_id, signature, signing_key_id, dsse_envelope, signed_at)
		VALUES
		  ($1, $2, $3, 3, $4,
		   'https://vsp.dev/buildtypes/scan-run/v1', $5, '', '{}'::jsonb,
		   '[]'::jsonb, '{}'::jsonb, $6,
		   $7, $8, $9, $10, NOW())`,
		c.TenantID,
		"vsp-scan-run/"+c.RID,
		"sha256:"+digestHex(c.RID+":"+c.TenantID),
		"https://vsp.dev/builders/gateway/v1",
		c.Source,
		stmtBytes,
		c.RunID, env.Signatures[0].Sig, env.Signatures[0].KeyID, envJSON,
	); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "persist: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"already_signed": false,
		"key_id":         signingKeyID,
		"envelope":       env,
	})
}

// HTTP — GET /api/v1/runs/{rid}/provenance
func handleRunProvenanceGet(w http.ResponseWriter, r *http.Request) {
	rid := strings.TrimSpace(chi.URLParam(r, "rid"))
	if rid == "" {
		writeJSONErr(w, http.StatusBadRequest, "rid required")
		return
	}
	if p4SQLDB == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "p4 db unavailable")
		return
	}
	c, err := loadRunForProvenance(r.Context(), p4SQLDB, rid)
	if err == sql.ErrNoRows {
		writeJSONErr(w, http.StatusNotFound, "run not found")
		return
	}
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "load run: "+err.Error())
		return
	}
	env := loadExistingProvenance(r.Context(), p4SQLDB, c.RunID)
	if env == nil {
		writeJSONErr(w, http.StatusNotFound, "no provenance recorded for this run")
		return
	}
	writeJSON(w, http.StatusOK, env)
}

// HTTP — GET /api/v1/runs/{rid}/provenance/verify
func handleRunProvenanceVerify(w http.ResponseWriter, r *http.Request) {
	rid := strings.TrimSpace(chi.URLParam(r, "rid"))
	if rid == "" {
		writeJSONErr(w, http.StatusBadRequest, "rid required")
		return
	}
	if p4SQLDB == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "p4 db unavailable")
		return
	}
	c, err := loadRunForProvenance(r.Context(), p4SQLDB, rid)
	if err == sql.ErrNoRows {
		writeJSONErr(w, http.StatusNotFound, "run not found")
		return
	}
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "load run: "+err.Error())
		return
	}
	env := loadExistingProvenance(r.Context(), p4SQLDB, c.RunID)
	if env == nil {
		writeJSONErr(w, http.StatusNotFound, "no provenance recorded for this run")
		return
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "decode payload: "+err.Error())
		return
	}
	if len(env.Signatures) == 0 {
		writeJSONErr(w, http.StatusInternalServerError, "envelope missing signature")
		return
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "decode sig: "+err.Error())
		return
	}
	pubPEM, err := publicKeyPEM()
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok, err := verifySignature(payload, sig, pubPEM)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "verify: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":   ok,
		"key_id":  env.Signatures[0].KeyID,
		"subject": "vsp-scan-run/" + c.RID,
	})
}

func loadExistingProvenance(ctx context.Context, db *sql.DB, runID string) *dsseEnvelope {
	var raw []byte
	err := db.QueryRowContext(ctx,
		`SELECT dsse_envelope FROM slsa_provenance
		  WHERE run_id = $1 AND dsse_envelope IS NOT NULL
		  ORDER BY created_at DESC LIMIT 1`, runID).Scan(&raw)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var env dsseEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil
	}
	return &env
}

func gatewayVersion() string {
	if v := os.Getenv("VSP_GATEWAY_VERSION"); v != "" {
		return v
	}
	return "dev"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func digestHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
