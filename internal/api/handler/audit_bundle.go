// Package handler — auditor evidence bundle.
//
// GET /api/v1/audit/bundle (admin only) → application/zip
//
// Builds a ZIP of every artefact a 3PAO / SOC 2 auditor / FedRAMP
// assessor wants for an authorisation review:
//
//   - manifest.json       — bundle metadata + checksums
//   - audit_log.jsonl     — full hash-chained audit log for the tenant
//   - evidence/*.{pdf,…}  — every compliance_evidence file
//   - slsa/*.json         — every signed SLSA provenance statement
//   - disclosures.json    — security disclosure history (timestamps + SLA only)
//   - tabletops.json      — incident response exercise log
//   - cato.json           — current cATO posture snapshot
//   - dora.json           — DORA metrics for the last 90 days
//   - improvement.json    — last 4 quarterly metric rollups
//   - README.txt          — guide for the assessor
//
// Pre-Sprint-8.6, an auditor would have to call ~10 endpoints and
// download evidence files individually. This bundle is the single
// artefact that makes a clean-room re-audit possible.
package handler

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type AuditBundle struct {
	DB *store.DB
}

func NewAuditBundle(db *store.DB) *AuditBundle { return &AuditBundle{DB: db} }

func (h *AuditBundle) Get(w http.ResponseWriter, r *http.Request) {
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

	now := time.Now().UTC()
	filename := fmt.Sprintf("vsp-audit-bundle-%s.zip", now.Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "private, no-store")

	zw := zip.NewWriter(w)
	defer zw.Close()

	// Track checksums so the manifest can pin every file's SHA-256.
	type fileMeta struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int    `json:"size_bytes"`
	}
	var files []fileMeta

	add := func(path string, data []byte) error {
		fw, err := zw.Create(path)
		if err != nil {
			return err
		}
		if _, err := fw.Write(data); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files = append(files, fileMeta{
			Path:   path,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   len(data),
		})
		return nil
	}

	ctx := r.Context()

	// 1. Audit log — JSONL, one row per audit entry, oldest first so the
	//    hash chain reads naturally.
	if buf, err := dumpAuditLog(ctx, h.DB.Pool(), tenantID); err == nil {
		_ = add("audit_log.jsonl", buf)
	}

	// 2. Compliance evidence files. Re-emit under evidence/<id>-<filename>
	//    so collisions are impossible.
	if rows, err := h.DB.Pool().Query(ctx,
		`SELECT id::text, filename, blob
		   FROM compliance_evidence WHERE tenant_id = $1`, tenantID); err == nil {
		for rows.Next() {
			var id, fname string
			var blob []byte
			if err := rows.Scan(&id, &fname, &blob); err == nil {
				_ = add("evidence/"+id+"-"+sanitizeForZip(fname), blob)
			}
		}
		rows.Close()
	}

	// 3. SLSA provenance — full DSSE envelopes per run.
	if rows, err := h.DB.Pool().Query(ctx,
		`SELECT artifact_name, dsse_envelope
		   FROM slsa_provenance
		  WHERE tenant_id = $1 AND dsse_envelope IS NOT NULL`, tenantID); err == nil {
		for rows.Next() {
			var name string
			var env []byte
			if err := rows.Scan(&name, &env); err == nil {
				_ = add("slsa/"+sanitizeForZip(name)+".json", env)
			}
		}
		rows.Close()
	}

	// 4. Disclosures — strip body content; only metadata + SLA hits travel.
	if buf, err := dumpDisclosureSummary(ctx, h.DB.Pool()); err == nil {
		_ = add("disclosures.json", buf)
	}

	// 5. Tabletop exercise log.
	if buf, err := dumpTabletops(ctx, h.DB.Pool(), tenantID); err == nil {
		_ = add("tabletops.json", buf)
	}

	// 6. cATO posture snapshot — call the live computation.
	if buf, err := snapshotJSON(func() any {
		return liveCATOSnapshot(ctx, h.DB, tenantID)
	}); err == nil {
		_ = add("cato.json", buf)
	}

	// 7. DORA snapshot.
	if buf, err := snapshotJSON(func() any {
		return liveDORASnapshot(ctx, h.DB, tenantID)
	}); err == nil {
		_ = add("dora.json", buf)
	}

	// 8. Improvement quarters.
	if buf, err := snapshotJSON(func() any {
		return liveImprovementSnapshot(ctx, h.DB, tenantID)
	}); err == nil {
		_ = add("improvement.json", buf)
	}

	// 9. README — assessor's guide. Plain ASCII so any zip viewer reads it.
	readme := buildReadme(tenantID, now, len(files))
	_ = add("README.txt", []byte(readme))

	// 10. Manifest LAST so it lists every prior file. Manifest itself
	//     is checksummed by inclusion in the zip but not in its own
	//     `files` array (would need a fixed-point computation).
	manifest := map[string]any{
		"generated_at": now.Format(time.RFC3339),
		"tenant_id":    tenantID,
		"files":        files,
		"about": "VSP audit evidence bundle. SHA-256 of each file is " +
			"pinned in this manifest; the manifest itself is part of the " +
			"zip so an assessor can verify integrity post-extraction.",
	}
	mbuf, _ := json.MarshalIndent(manifest, "", "  ")
	if fw, err := zw.Create("manifest.json"); err == nil {
		_, _ = fw.Write(mbuf)
	}

	logAudit(r, h.DB, "AUDIT_BUNDLE_EXPORTED", "audit_bundle/"+tenantID)
}

// ── helpers ────────────────────────────────────────────────────────────────

func sanitizeForZip(name string) string {
	if name == "" {
		return "unnamed"
	}
	name = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r < 0x20 {
			return '_'
		}
		return r
	}, name)
	if len(name) > 200 {
		name = name[:200]
	}
	return name
}

func dumpAuditLog(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]byte, error) {
	rows, err := pool.Query(ctx,
		`SELECT seq, action, COALESCE(resource,''), COALESCE(ip,''),
		        hash, COALESCE(prev_hash,''), created_at
		   FROM audit_log WHERE tenant_id = $1
		  ORDER BY seq ASC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out strings.Builder
	for rows.Next() {
		var seq int64
		var action, resource, ip, hash, prev string
		var ts time.Time
		if err := rows.Scan(&seq, &action, &resource, &ip, &hash, &prev, &ts); err != nil {
			continue
		}
		row := map[string]any{
			"seq":        seq,
			"action":     action,
			"resource":   resource,
			"ip":         ip,
			"hash":       hash,
			"prev_hash":  prev,
			"created_at": ts.Format(time.RFC3339Nano),
		}
		b, _ := json.Marshal(row)
		out.Write(b)
		out.WriteByte('\n')
	}
	return []byte(out.String()), nil
}

func dumpDisclosureSummary(ctx context.Context, pool *pgxpool.Pool) ([]byte, error) {
	rows, err := pool.Query(ctx,
		`SELECT COALESCE(public_ref,''), title, COALESCE(severity,''), status,
		        submitted_at, ack_due_at, acknowledged_at, triaged_at,
		        resolved_at
		   FROM security_disclosures
		  ORDER BY submitted_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type item struct {
		PublicRef      string     `json:"public_ref"`
		Title          string     `json:"title"`
		Severity       string     `json:"severity"`
		Status         string     `json:"status"`
		SubmittedAt    time.Time  `json:"submitted_at"`
		AckDueAt       time.Time  `json:"ack_due_at"`
		AcknowledgedAt *time.Time `json:"acknowledged_at"`
		TriagedAt      *time.Time `json:"triaged_at"`
		ResolvedAt     *time.Time `json:"resolved_at"`
		AckHitSLA      bool       `json:"ack_hit_sla"`
	}
	var out []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.PublicRef, &it.Title, &it.Severity, &it.Status,
			&it.SubmittedAt, &it.AckDueAt, &it.AcknowledgedAt, &it.TriagedAt,
			&it.ResolvedAt); err == nil {
			it.AckHitSLA = it.AcknowledgedAt != nil && !it.AcknowledgedAt.After(it.AckDueAt)
			out = append(out, it)
		}
	}
	return json.MarshalIndent(out, "", "  ")
}

func dumpTabletops(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]byte, error) {
	rows, err := pool.Query(ctx,
		`SELECT scenario_kind, title, scenario_text, conducted_at,
		        duration_min, participants, facilitator, observations,
		        action_items, rating
		   FROM tabletop_exercises WHERE tenant_id = $1
		  ORDER BY conducted_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type item struct {
		Scenario     string          `json:"scenario_kind"`
		Title        string          `json:"title"`
		ScenarioText string          `json:"scenario_text"`
		ConductedAt  time.Time       `json:"conducted_at"`
		DurationMin  int             `json:"duration_min"`
		Participants string          `json:"participants"`
		Facilitator  string          `json:"facilitator"`
		Observations string          `json:"observations"`
		ActionItems  json.RawMessage `json:"action_items"`
		Rating       string          `json:"rating"`
	}
	var out []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.Scenario, &it.Title, &it.ScenarioText,
			&it.ConductedAt, &it.DurationMin, &it.Participants, &it.Facilitator,
			&it.Observations, &it.ActionItems, &it.Rating); err == nil {
			out = append(out, it)
		}
	}
	return json.MarshalIndent(out, "", "  ")
}

// snapshotJSON wraps a function returning any into pretty JSON. The
// indirection lets the bundle code stay flat instead of weaving live
// handler calls through fake http.ResponseWriters.
func snapshotJSON(fn func() any) ([]byte, error) {
	v := fn()
	if v == nil {
		return []byte("null"), nil
	}
	return json.MarshalIndent(v, "", "  ")
}

// liveCATOSnapshot / liveDORASnapshot / liveImprovementSnapshot are
// thin wrappers that re-use the per-criterion logic from the live
// endpoints. Implemented as method-free helpers so the bundle code
// doesn't have to know about request lifecycle.
func liveCATOSnapshot(ctx context.Context, db *store.DB, tenantID string) any {
	// Lightweight snapshot — same shape as /api/v1/cato but without
	// running through the http handler so we don't fake a request.
	c := &CATO{DB: db}
	r := &http.Request{}
	r = r.WithContext(ctx)
	criteria := []catoCriterion{
		c.checkAuditChain(r, tenantID),
		c.checkDriftAck(r, tenantID),
		c.checkEvidenceFreshness(r, tenantID),
		c.checkScanCadence(r, tenantID),
		c.checkPOAM(r, tenantID),
		c.checkIncidentReporting(r, tenantID),
		c.checkSBOMCoverage(r, tenantID),
	}
	pass, warn, fail := 0, 0, 0
	for _, cr := range criteria {
		switch cr.Status {
		case "pass":
			pass++
		case "warn":
			warn++
		case "fail":
			fail++
		}
	}
	overall := "ready"
	if fail > 0 {
		overall = "blocked"
	} else if warn > 0 {
		overall = "at_risk"
	}
	return map[string]any{
		"overall":  overall,
		"summary":  map[string]int{"pass": pass, "warn": warn, "fail": fail, "total": len(criteria)},
		"criteria": criteria,
		"as_of":    time.Now().UTC().Format(time.RFC3339),
	}
}

func liveDORASnapshot(ctx context.Context, db *store.DB, tenantID string) any {
	d := &DORA{DB: db}
	r := &http.Request{}
	r = r.WithContext(ctx)
	const days = 90
	cur := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	prev := time.Now().Add(-time.Duration(2*days) * 24 * time.Hour)
	return map[string]any{
		"window_days":         days,
		"deploy_frequency":    d.deployFrequency(r, tenantID, cur, prev, days),
		"lead_time":           d.leadTime(r, tenantID, cur, prev),
		"mttr":                d.mttr(r, tenantID, cur, prev),
		"change_failure_rate": d.changeFailureRate(r, tenantID, cur, prev),
		"as_of":               time.Now().UTC().Format(time.RFC3339),
	}
}

func liveImprovementSnapshot(ctx context.Context, db *store.DB, tenantID string) any {
	imp := &Improvement{DB: db}
	r := &http.Request{}
	r = r.WithContext(ctx)
	now := time.Now().UTC()
	quarters := lastNQuarters(now, 4)
	out := make([]quarterRow, 0, len(quarters))
	for _, q := range quarters {
		out = append(out, imp.computeQuarter(r, tenantID, q))
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return map[string]any{"quarters": out}
}

func buildReadme(tenantID string, generatedAt time.Time, fileCount int) string {
	return `VSP Audit Evidence Bundle
==========================

Generated:  ` + generatedAt.Format(time.RFC3339) + `
Tenant:     ` + tenantID + `
Files:      ` + fmt.Sprint(fileCount) + ` (excluding manifest.json + this README)

Contents
--------
manifest.json        SHA-256 of every file in this bundle.
audit_log.jsonl      Hash-chained audit log; verify with the platform's
                     /api/v1/audit/verify endpoint or by re-hashing
                     each row against its predecessor.
evidence/            Compliance evidence files (SSP, FIPS-199, etc.)
                     uploaded by the tenant under /api/v1/compliance/
                     evidence. Filename format: <id>-<original>.
slsa/                In-toto v1 / DSSE attestations for every signed
                     scan run. Compatible with cosign verify-attestation.
disclosures.json     Security disclosure intake history with SLA hits.
tabletops.json       Incident-response tabletop exercise log.
cato.json            Live continuous-ATO posture snapshot.
dora.json            DORA metrics over the last 90 days.
improvement.json     Quarterly KPI rollup over the last 4 quarters.

Verifying the bundle
--------------------
1. Extract the zip.
2. For each file in manifest.json, compute SHA-256 and compare. A
   mismatch means the bundle was modified after generation.
3. Re-run audit chain verification:
     curl -X POST <gateway>/api/v1/audit/verify \
          -H "Authorization: Bearer <admin-token>"
   The response includes the same audit_log.jsonl entries — they
   should match line-for-line.
4. Re-verify any SLSA attestation:
     cosign verify-attestation --key vsp-public.pem <subject>
   The public key is published at /.well-known/pgp-key.txt.
`
}
