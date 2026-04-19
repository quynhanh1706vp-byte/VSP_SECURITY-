package main

// Incident Response + CIRCIA + Forensics
// References:
//   NIST SP 800-61 Rev.3 (April 2025) — Incident Response Guide
//   NIST SP 800-184 — Event Recovery
//   NIST SP 800-86 — Forensics (chain of custody)
//   CIRCIA 2022 — 72h substantial / 24h ransomware reporting
//   EO 14028 — Nation's Cybersecurity

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lib/pq"
)

// ════════════════════════════════════════════════════════════════
// Helper: parse string array from pq
// ════════════════════════════════════════════════════════════════

// GET /api/p4/ir/incidents
// Query params: phase, severity, status, substantial, limit
func handleIRIncidentsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if p4SQLDB == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"incidents": []any{}})
		return
	}

	q := r.URL.Query()
	query := `SELECT incident_id, title, phase, severity, category, status,
	                 is_substantial, is_ransomware, ransom_paid,
	                 detected_at, closed_at, assigned_to
	          FROM ir_incidents WHERE 1=1`
	args := []any{}
	i := 1
	if ph := q.Get("phase"); ph != "" {
		query += fmt.Sprintf(" AND phase = $%d", i)
		args = append(args, ph)
		i++
	}
	if sv := q.Get("severity"); sv != "" {
		query += fmt.Sprintf(" AND severity = $%d", i)
		args = append(args, sv)
		i++
	}
	if st := q.Get("status"); st != "" {
		query += fmt.Sprintf(" AND status = $%d", i)
		args = append(args, st)
		i++
	}
	if q.Get("substantial") == "true" {
		query += " AND is_substantial = true"
	}
	if q.Get("ransomware") == "true" {
		query += " AND is_ransomware = true"
	}
	query += " ORDER BY detected_at DESC LIMIT 100"

	rows, err := p4SQLDB.Query(query, args...)
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}
	defer rows.Close()

	var list []map[string]any
	stats := map[string]int{"open": 0, "investigating": 0, "contained": 0, "resolved": 0, "closed": 0, "false_positive": 0}
	phases := map[string]int{}
	severities := map[string]int{}
	substantial := 0
	ransomware := 0
	for rows.Next() {
		var incID, title, phase, severity, status string
		var category, assignedTo sql.NullString
		var isSub, isRan, ransomPaid bool
		var detected time.Time
		var closed sql.NullTime
		if err := rows.Scan(&incID, &title, &phase, &severity, &category, &status,
			&isSub, &isRan, &ransomPaid, &detected, &closed, &assignedTo); err == nil {
			list = append(list, map[string]any{
				"incident_id":    incID,
				"title":          title,
				"phase":          phase,
				"severity":       severity,
				"category":       category.String,
				"status":         status,
				"is_substantial": isSub,
				"is_ransomware":  isRan,
				"ransom_paid":    ransomPaid,
				"detected_at":    detected,
				"closed_at":      closed.Time,
				"assigned_to":    assignedTo.String,
			})
			stats[status]++
			phases[phase]++
			severities[severity]++
			if isSub {
				substantial++
			}
			if isRan {
				ransomware++
			}
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"incidents": list,
		"count":     len(list),
		"stats": map[string]any{
			"by_status":   stats,
			"by_phase":    phases,
			"by_severity": severities,
			"substantial": substantial,
			"ransomware":  ransomware,
		},
	})
}

// POST /api/p4/ir/incident
// Create a new incident
func handleIRIncidentCreate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}

	var req struct {
		Title                 string `json:"title"`
		Description           string `json:"description"`
		Severity              string `json:"severity"`
		Category              string `json:"category"`
		IsSubstantial         bool   `json:"is_substantial"`
		IsRansomware          bool   `json:"is_ransomware"`
		ImpactConfidentiality bool   `json:"impact_confidentiality"`
		ImpactIntegrity       bool   `json:"impact_integrity"`
		ImpactAvailability    bool   `json:"impact_availability"`
		ImpactSafety          bool   `json:"impact_safety"`
		ImpactBusinessOps     bool   `json:"impact_business_ops"`
		ImpactSupplyChain     bool   `json:"impact_supply_chain"`
		Reporter              string `json:"reporter"`
		AssignedTo            string `json:"assigned_to"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if req.Title == "" {
		http.Error(w, "title required", 400)
		return
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}

	// Auto-flag substantial based on CIRCIA criteria
	if req.ImpactConfidentiality || req.ImpactIntegrity || req.ImpactAvailability ||
		req.ImpactSafety || req.ImpactBusinessOps || req.ImpactSupplyChain {
		req.IsSubstantial = true
	}

	// Generate incident ID: INC-YYYY-NNNN
	year := time.Now().Year()
	var nextNum int
	_ = p4SQLDB.QueryRow(`
		SELECT COUNT(*) + 1 FROM ir_incidents WHERE incident_id LIKE $1
	`, fmt.Sprintf("INC-%d-%%", year)).Scan(&nextNum)
	incID := fmt.Sprintf("INC-%d-%04d", year, nextNum)

	_, err := p4SQLDB.Exec(`
		INSERT INTO ir_incidents
		(tenant_id, incident_id, title, description, severity, category,
		 is_substantial, is_ransomware,
		 impact_confidentiality, impact_integrity, impact_availability,
		 impact_safety, impact_business_ops, impact_supply_chain,
		 detected_at, reporter, assigned_to, phase, status)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6,''),
		        $7, $8, $9, $10, $11, $12, $13, $14,
		        NOW(), $15, $16, 'detection_analysis', 'open')
	`, defaultTenantID(), incID, req.Title, req.Description, req.Severity, req.Category,
		req.IsSubstantial, req.IsRansomware,
		req.ImpactConfidentiality, req.ImpactIntegrity, req.ImpactAvailability,
		req.ImpactSafety, req.ImpactBusinessOps, req.ImpactSupplyChain,
		req.Reporter, req.AssignedTo)
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}

	response := map[string]any{
		"created":        true,
		"incident_id":    incID,
		"is_substantial": req.IsSubstantial,
		"is_ransomware":  req.IsRansomware,
	}

	// If substantial or ransomware, include CIRCIA deadline reminder
	if req.IsSubstantial {
		response["circia_deadline_72h"] = time.Now().Add(72 * time.Hour)
		response["circia_action"] = "72-hour CIRCIA report REQUIRED for substantial incidents"
	}
	if req.IsRansomware {
		response["circia_deadline_24h_ransom"] = time.Now().Add(24 * time.Hour)
		response["circia_action_ransom"] = "If ransom paid: 24-hour CIRCIA report REQUIRED"
	}

	_ = json.NewEncoder(w).Encode(response)
}

// POST /api/p4/ir/incident/transition
// Body: {"incident_id": "INC-2026-0003", "phase": "containment", "notes": "..."}
func handleIRIncidentTransition(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}

	var req struct {
		IncidentID string `json:"incident_id"`
		Phase      string `json:"phase"`
		Status     string `json:"status"`
		Notes      string `json:"notes"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	validPhases := map[string]bool{
		"preparation": true, "detection_analysis": true, "containment": true,
		"eradication": true, "recovery": true, "post_incident": true,
	}
	if req.Phase != "" && !validPhases[req.Phase] {
		http.Error(w, "invalid phase", 400)
		return
	}

	// Map phase → timeline column
	phaseTimeCol := map[string]string{
		"containment":   "contained_at",
		"eradication":   "eradicated_at",
		"recovery":      "recovered_at",
		"post_incident": "closed_at",
	}

	sets := []string{"phase = $1", "updated_at = NOW()"}
	args := []any{req.Phase}
	i := 2

	if req.Status != "" {
		sets = append(sets, fmt.Sprintf("status = $%d", i))
		args = append(args, req.Status)
		i++
	}

	if col, ok := phaseTimeCol[req.Phase]; ok {
		sets = append(sets, fmt.Sprintf("%s = NOW()", col))
	}

	args = append(args, req.IncidentID)
	query := fmt.Sprintf("UPDATE ir_incidents SET %s WHERE incident_id = $%d",
		strings.Join(sets, ", "), i)

	res, err := p4SQLDB.Exec(query, args...)
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "incident not found", 404)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"updated":     true,
		"incident_id": req.IncidentID,
		"phase":       req.Phase,
		"status":      req.Status,
	})
}

// ════════════════════════════════════════════════════════════════
// CIRCIA Reports
// ════════════════════════════════════════════════════════════════

// POST /api/p4/circia/generate
// Auto-generate CIRCIA report from an existing incident
func handleCIRCIAGenerate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}

	var req struct {
		IncidentID string `json:"incident_id"`
		ReportType string `json:"report_type"` // substantial_incident | ransomware_payment | joint | supplemental
		CISector   string `json:"ci_sector"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	// Load incident
	var incUUID, title, desc, severity, status string
	var isSub, isRan, ransomPaid bool
	var ransomAmount sql.NullFloat64
	var detected time.Time
	var cat sql.NullString

	err := p4SQLDB.QueryRow(`
		SELECT id, title, COALESCE(description,''), severity, status,
		       is_substantial, is_ransomware, ransom_paid, ransom_amount_usd,
		       detected_at, category
		FROM ir_incidents WHERE incident_id = $1
	`, req.IncidentID).Scan(&incUUID, &title, &desc, &severity, &status,
		&isSub, &isRan, &ransomPaid, &ransomAmount, &detected, &cat)
	if err != nil {
		http.Error(w, "incident not found: "+err.Error(), 404)
		return
	}

	// Auto-detect type if not specified
	if req.ReportType == "" {
		if ransomPaid {
			req.ReportType = "ransomware_payment"
		} else if isSub {
			req.ReportType = "substantial_incident"
		} else {
			http.Error(w, "incident is not substantial or ransomware, no CIRCIA report required", 400)
			return
		}
	}

	// Calculate deadline
	var deadline time.Time
	switch req.ReportType {
	case "ransomware_payment":
		deadline = detected.Add(24 * time.Hour)
	case "substantial_incident", "joint":
		deadline = detected.Add(72 * time.Hour)
	case "supplemental":
		deadline = time.Now().Add(24 * time.Hour) // promptly
	}

	hoursElapsed := time.Since(detected).Hours()

	reportUUID := generateUUID()

	// Build full report JSON per CIRCIA NPRM
	report := map[string]any{
		"report_uuid":   reportUUID,
		"report_type":   req.ReportType,
		"regulation":    "CIRCIA 2022 (Cyber Incident Reporting for Critical Infrastructure Act)",
		"submitting_to": "CISA (Cybersecurity and Infrastructure Security Agency)",
		"ci_sector":     req.CISector,
		"covered_entity": map[string]any{
			"name":    "VSP Security Platform",
			"website": "https://vsp.local",
		},
		"incident": map[string]any{
			"incident_id":    req.IncidentID,
			"title":          title,
			"description":    desc,
			"severity":       severity,
			"category":       cat.String,
			"detected_at":    detected,
			"is_substantial": isSub,
			"is_ransomware":  isRan,
		},
		"timeline": map[string]any{
			"incident_detected_at": detected,
			"report_deadline":      deadline,
			"hours_elapsed":        fmt.Sprintf("%.2f", hoursElapsed),
			"deadline_hours_total": map[string]int{"ransomware_payment": 24, "substantial_incident": 72}[req.ReportType],
		},
		"ransomware": map[string]any{
			"ransom_paid":       ransomPaid,
			"ransom_amount_usd": ransomAmount.Float64,
		},
		"generated_at": time.Now(),
		"status":       "draft",
		"next_steps": []string{
			"Review draft content",
			"Add indicators of compromise (IOCs)",
			"Document attack vector + affected systems",
			"Executive review",
			"Submit to CISA before deadline",
		},
	}

	reportJSON, _ := json.Marshal(report)

	// Persist draft
	_, err = p4SQLDB.Exec(`
		INSERT INTO circia_reports
		(tenant_id, incident_id, report_uuid, report_type, ci_sector,
		 incident_detected_at, deadline_at, hours_elapsed,
		 narrative_description, ransom_paid_amount_usd, status, report_json)
		VALUES ($1, $2, $3, $4, NULLIF($5,''), $6, $7, $8, $9, $10, 'draft', $11)
	`, defaultTenantID(), incUUID, reportUUID, req.ReportType, req.CISector,
		detected, deadline, hoursElapsed, desc, ransomAmount.Float64, reportJSON)
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}

	_ = json.NewEncoder(w).Encode(report)
}

// POST /api/p4/circia/submit
// Body: {"report_uuid": "...", "submitted_by_name":"...", "submitted_by_title":"...", "submitted_by_email":"..."}
func handleCIRCIASubmit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}

	var req struct {
		ReportUUID       string `json:"report_uuid"`
		SubmittedByName  string `json:"submitted_by_name"`
		SubmittedByTitle string `json:"submitted_by_title"`
		SubmittedByEmail string `json:"submitted_by_email"`
		CISASubmissionID string `json:"cisa_submission_id"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	cisaID := req.CISASubmissionID
	if cisaID == "" {
		// Simulated CISA ref (in production, call CISA API)
		cisaID = "CISA-" + generateUUID()[:12]
	}

	_, err := p4SQLDB.Exec(`
		UPDATE circia_reports
		SET submitted_at = NOW(), status = 'submitted',
		    submitted_by_name = $1, submitted_by_title = $2, submitted_by_email = $3,
		    cisa_submission_id = $4, updated_at = NOW()
		WHERE report_uuid = $5
	`, req.SubmittedByName, req.SubmittedByTitle, req.SubmittedByEmail, cisaID, req.ReportUUID)
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}

	// Check deadline compliance
	var deadlineMet bool
	_ = p4SQLDB.QueryRow(`
		SELECT deadline_met FROM circia_reports WHERE report_uuid = $1
	`, req.ReportUUID).Scan(&deadlineMet)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"submitted":          true,
		"report_uuid":        req.ReportUUID,
		"cisa_submission_id": cisaID,
		"deadline_met":       deadlineMet,
		"submitted_at":       time.Now(),
	})
}

// GET /api/p4/circia/reports
func handleCIRCIAList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if p4SQLDB == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"reports": []any{}})
		return
	}

	rows, err := p4SQLDB.Query(`
		SELECT c.report_uuid, c.report_type, c.ci_sector, c.status,
		       c.incident_detected_at, c.deadline_at, c.submitted_at, c.deadline_met,
		       c.hours_elapsed, c.cisa_submission_id, c.submitted_by_name,
		       i.incident_id, i.title
		FROM circia_reports c
		LEFT JOIN ir_incidents i ON c.incident_id = i.id
		ORDER BY c.created_at DESC LIMIT 100
	`)
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}
	defer rows.Close()

	var list []map[string]any
	stats := map[string]int{"draft": 0, "submitted": 0, "acknowledged": 0}
	deadlineCompliance := map[string]int{"met": 0, "missed": 0, "pending": 0}
	for rows.Next() {
		var uuid, rtype, status string
		var sector, cisaID, submittedBy, incidentID, incidentTitle sql.NullString
		var detected, deadline time.Time
		var submitted sql.NullTime
		var hoursElapsed sql.NullFloat64
		var deadlineMet sql.NullBool
		if err := rows.Scan(&uuid, &rtype, &sector, &status,
			&detected, &deadline, &submitted, &deadlineMet, &hoursElapsed,
			&cisaID, &submittedBy, &incidentID, &incidentTitle); err == nil {
			list = append(list, map[string]any{
				"report_uuid":        uuid,
				"report_type":        rtype,
				"ci_sector":          sector.String,
				"status":             status,
				"incident_id":        incidentID.String,
				"incident_title":     incidentTitle.String,
				"detected_at":        detected,
				"deadline_at":        deadline,
				"submitted_at":       submitted.Time,
				"deadline_met":       deadlineMet.Bool,
				"hours_elapsed":      hoursElapsed.Float64,
				"cisa_submission_id": cisaID.String,
				"submitted_by":       submittedBy.String,
			})
			stats[status]++
			if !submitted.Valid {
				deadlineCompliance["pending"]++
			} else if deadlineMet.Bool {
				deadlineCompliance["met"]++
			} else {
				deadlineCompliance["missed"]++
			}
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"reports":             list,
		"count":               len(list),
		"by_status":           stats,
		"deadline_compliance": deadlineCompliance,
	})
}

// ════════════════════════════════════════════════════════════════
// Forensics Evidence
// ════════════════════════════════════════════════════════════════

// POST /api/p4/forensics/evidence
func handleForensicsCreate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}

	var req struct {
		IncidentID       string `json:"incident_id"` // INC-2026-0001
		EvidenceType     string `json:"evidence_type"`
		Description      string `json:"description"`
		FilePath         string `json:"file_path"`
		FileSize         int64  `json:"file_size_bytes"`
		FileHashSHA256   string `json:"file_hash_sha256"`
		CollectedBy      string `json:"collected_by"`
		CollectionMethod string `json:"collection_method"`
		SourceSystem     string `json:"source_system"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	// Lookup incident UUID
	var incUUID string
	err := p4SQLDB.QueryRow(`SELECT id FROM ir_incidents WHERE incident_id = $1`,
		req.IncidentID).Scan(&incUUID)
	if err != nil {
		http.Error(w, "incident not found", 404)
		return
	}

	// Generate evidence ID
	year := time.Now().Year()
	var nextNum int
	_ = p4SQLDB.QueryRow(`
		SELECT COUNT(*) + 1 FROM forensics_evidence WHERE evidence_id LIKE $1
	`, fmt.Sprintf("EVD-%d-%%", year)).Scan(&nextNum)
	evID := fmt.Sprintf("EVD-%d-%04d", year, nextNum)

	// Initial custody log entry
	custodyLog := []map[string]any{{
		"timestamp": time.Now(),
		"actor":     req.CollectedBy,
		"action":    "initial_collection",
		"location":  req.SourceSystem,
		"notes":     fmt.Sprintf("Collected via %s", req.CollectionMethod),
	}}
	custodyJSON, _ := json.Marshal(custodyLog)

	_, err = p4SQLDB.Exec(`
		INSERT INTO forensics_evidence
		(tenant_id, incident_id, evidence_id, evidence_type, description,
		 file_path, file_size_bytes, file_hash_sha256,
		 collected_by, collected_at, collection_method, source_system, custody_log)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), NULLIF($7,0::bigint), NULLIF($8,''),
		        $9, NOW(), NULLIF($10,''), NULLIF($11,''), $12)
	`, defaultTenantID(), incUUID, evID, req.EvidenceType, req.Description,
		req.FilePath, req.FileSize, req.FileHashSHA256,
		req.CollectedBy, req.CollectionMethod, req.SourceSystem, custodyJSON)
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"created":     true,
		"evidence_id": evID,
		"incident_id": req.IncidentID,
		"hash":        req.FileHashSHA256,
	})
}

// GET /api/p4/forensics/evidence?incident=INC-2026-0001
func handleForensicsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if p4SQLDB == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"evidence": []any{}})
		return
	}

	incFilter := r.URL.Query().Get("incident")
	query := `SELECT f.evidence_id, f.evidence_type, f.description, f.file_size_bytes,
	                 f.file_hash_sha256, f.collected_by, f.collected_at,
	                 f.collection_method, f.source_system, f.analyzed,
	                 f.custody_log, i.incident_id
	          FROM forensics_evidence f
	          LEFT JOIN ir_incidents i ON f.incident_id = i.id
	          WHERE 1=1`
	args := []any{}
	i := 1
	if incFilter != "" {
		query += fmt.Sprintf(" AND i.incident_id = $%d", i)
		args = append(args, incFilter)
		i++
	}
	query += " ORDER BY f.collected_at DESC LIMIT 100"

	rows, err := p4SQLDB.Query(query, args...)
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	defer rows.Close()

	var list []map[string]any
	byType := map[string]int{}
	for rows.Next() {
		var evID, evType, desc string
		var fileSize sql.NullInt64
		var hash, collectedBy, method, source, incidentID sql.NullString
		var collected time.Time
		var analyzed bool
		var custody []byte
		if err := rows.Scan(&evID, &evType, &desc, &fileSize, &hash,
			&collectedBy, &collected, &method, &source, &analyzed,
			&custody, &incidentID); err == nil {
			var custodyArr any
			_ = json.Unmarshal(custody, &custodyArr)
			list = append(list, map[string]any{
				"evidence_id":       evID,
				"evidence_type":     evType,
				"description":       desc,
				"file_size_bytes":   fileSize.Int64,
				"file_hash_sha256":  hash.String,
				"collected_by":      collectedBy.String,
				"collected_at":      collected,
				"collection_method": method.String,
				"source_system":     source.String,
				"analyzed":          analyzed,
				"incident_id":       incidentID.String,
				"custody_log":       custodyArr,
			})
			byType[evType]++
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"evidence": list,
		"count":    len(list),
		"by_type":  byType,
	})
}

// POST /api/p4/forensics/custody
// Add chain-of-custody entry
// Body: {"evidence_id": "EVD-2026-0001", "actor": "...", "action": "...", "location": "..."}
func handleForensicsCustody(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}

	var req struct {
		EvidenceID string `json:"evidence_id"`
		Actor      string `json:"actor"`
		Action     string `json:"action"`
		Location   string `json:"location"`
		Notes      string `json:"notes"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	entry := map[string]any{
		"timestamp": time.Now(),
		"actor":     req.Actor,
		"action":    req.Action,
		"location":  req.Location,
		"notes":     req.Notes,
	}
	entryJSON, _ := json.Marshal(entry)

	_, err := p4SQLDB.Exec(`
		UPDATE forensics_evidence
		SET custody_log = custody_log || $1::jsonb, updated_at = NOW()
		WHERE evidence_id = $2
	`, entryJSON, req.EvidenceID)
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"updated":     true,
		"evidence_id": req.EvidenceID,
		"entry":       entry,
	})
}

// ════════════════════════════════════════════════════════════════
// IR Playbooks
// ════════════════════════════════════════════════════════════════

// GET /api/p4/ir/playbooks
func handleIRPlaybooksList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if p4SQLDB == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"playbooks": []any{}})
		return
	}

	rows, err := p4SQLDB.Query(`
		SELECT playbook_id, name, description, incident_types, phases,
		       last_exercised, exercise_frequency_days, author
		FROM ir_playbooks ORDER BY playbook_id
	`)
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	defer rows.Close()

	var list []map[string]any
	for rows.Next() {
		var pid, name, desc, author string
		var types pq.StringArray
		var phases []byte
		var lastExercised sql.NullTime
		var freq int
		if err := rows.Scan(&pid, &name, &desc, &types, &phases,
			&lastExercised, &freq, &author); err == nil {
			var phasesObj any
			_ = json.Unmarshal(phases, &phasesObj)
			list = append(list, map[string]any{
				"playbook_id":    pid,
				"name":           name,
				"description":    desc,
				"incident_types": []string(types),
				"phases":         phasesObj,
				"last_exercised": lastExercised.Time,
				"exercise_freq":  freq,
				"author":         author,
			})
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"playbooks": list,
		"count":     len(list),
	})
}

// ════════════════════════════════════════════════════════════════
// Extended handlers for detail view + edit + ransom payment
// ════════════════════════════════════════════════════════════════

// GET /api/p4/ir/incident/detail?id=INC-2026-0001
func handleIRIncidentDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	incID := r.URL.Query().Get("id")
	if incID == "" {
		http.Error(w, "id required", 400)
		return
	}

	var uuid, title, desc, phase, severity, status string
	var cat, reporter, assignedTo, commander, lessons, rootCause sql.NullString
	var isSub, isRan, ransomPaid, impC, impI, impA, impS, impB, impSC bool
	var ransomAmount sql.NullFloat64
	var detected time.Time
	var confirmed, contained, eradicated, recovered, closed sql.NullTime
	var ransomPaidAt sql.NullTime
	var correctiveActions []byte

	err := p4SQLDB.QueryRow(`
		SELECT id, title, COALESCE(description,''), phase, severity, status,
		       category, reporter, assigned_to, incident_commander,
		       lessons_learned, root_cause, corrective_actions,
		       is_substantial, is_ransomware, ransom_paid, ransom_amount_usd, ransom_paid_at,
		       impact_confidentiality, impact_integrity, impact_availability,
		       impact_safety, impact_business_ops, impact_supply_chain,
		       detected_at, confirmed_at, contained_at, eradicated_at, recovered_at, closed_at
		FROM ir_incidents WHERE incident_id = $1
	`, incID).Scan(&uuid, &title, &desc, &phase, &severity, &status,
		&cat, &reporter, &assignedTo, &commander,
		&lessons, &rootCause, &correctiveActions,
		&isSub, &isRan, &ransomPaid, &ransomAmount, &ransomPaidAt,
		&impC, &impI, &impA, &impS, &impB, &impSC,
		&detected, &confirmed, &contained, &eradicated, &recovered, &closed)
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)
		return
	}

	var actions any
	_ = json.Unmarshal(correctiveActions, &actions)

	var reports []map[string]any
	rows, _ := p4SQLDB.Query(`
		SELECT report_uuid, report_type, status, deadline_at, submitted_at, deadline_met, cisa_submission_id
		FROM circia_reports WHERE incident_id = $1 ORDER BY created_at
	`, uuid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ruuid, rtype, rstatus string
			var rdeadline time.Time
			var rsubmitted sql.NullTime
			var rmet sql.NullBool
			var rcisa sql.NullString
			if err := rows.Scan(&ruuid, &rtype, &rstatus, &rdeadline, &rsubmitted, &rmet, &rcisa); err == nil {
				reports = append(reports, map[string]any{
					"report_uuid":        ruuid,
					"report_type":        rtype,
					"status":             rstatus,
					"deadline_at":        rdeadline,
					"submitted_at":       rsubmitted.Time,
					"deadline_met":       rmet.Bool,
					"cisa_submission_id": rcisa.String,
				})
			}
		}
	}

	var evidence []map[string]any
	rows2, _ := p4SQLDB.Query(`
		SELECT evidence_id, evidence_type, description, file_size_bytes, file_hash_sha256,
		       collected_by, collected_at, jsonb_array_length(custody_log) AS custody_count
		FROM forensics_evidence WHERE incident_id = $1 ORDER BY collected_at
	`, uuid)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var evID, evType, evDesc string
			var size sql.NullInt64
			var hash, collectedBy sql.NullString
			var collected time.Time
			var custodyCount int
			if err := rows2.Scan(&evID, &evType, &evDesc, &size, &hash, &collectedBy, &collected, &custodyCount); err == nil {
				evidence = append(evidence, map[string]any{
					"evidence_id":      evID,
					"evidence_type":    evType,
					"description":      evDesc,
					"file_size_bytes":  size.Int64,
					"file_hash_sha256": hash.String,
					"collected_by":     collectedBy.String,
					"collected_at":     collected,
					"custody_count":    custodyCount,
				})
			}
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"incident_id":        incID,
		"uuid":               uuid,
		"title":              title,
		"description":        desc,
		"phase":              phase,
		"severity":           severity,
		"status":             status,
		"category":           cat.String,
		"reporter":           reporter.String,
		"assigned_to":        assignedTo.String,
		"incident_commander": commander.String,
		"lessons_learned":    lessons.String,
		"root_cause":         rootCause.String,
		"corrective_actions": actions,
		"is_substantial":     isSub,
		"is_ransomware":      isRan,
		"ransom_paid":        ransomPaid,
		"ransom_amount_usd":  ransomAmount.Float64,
		"ransom_paid_at":     ransomPaidAt.Time,
		"impact": map[string]bool{
			"confidentiality": impC, "integrity": impI, "availability": impA,
			"safety": impS, "business_ops": impB, "supply_chain": impSC,
		},
		"timeline": map[string]any{
			"detected_at":   detected,
			"confirmed_at":  confirmed.Time,
			"contained_at":  contained.Time,
			"eradicated_at": eradicated.Time,
			"recovered_at":  recovered.Time,
			"closed_at":     closed.Time,
		},
		"circia_reports": reports,
		"forensics":      evidence,
	})
}

// POST /api/p4/ir/incident/update
func handleIRIncidentUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		IncidentID string `json:"incident_id"`
		Field      string `json:"field"`
		Value      string `json:"value"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	allowed := map[string]bool{
		"severity": true, "status": true, "description": true,
		"assigned_to": true, "incident_commander": true,
		"lessons_learned": true, "root_cause": true, "title": true,
	}
	if !allowed[req.Field] {
		http.Error(w, "field not updatable", 400)
		return
	}
	query := fmt.Sprintf("UPDATE ir_incidents SET %s = $1, updated_at = NOW() WHERE incident_id = $2", req.Field)
	res, err := p4SQLDB.Exec(query, req.Value, req.IncidentID)
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "incident not found", 404)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"updated": true, "incident_id": req.IncidentID,
		"field": req.Field, "new_value": req.Value,
	})
}

// POST /api/p4/ir/incident/ransom-payment
func handleIRRansomPayment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		IncidentID    string  `json:"incident_id"`
		AmountUSD     float64 `json:"amount_usd"`
		PaymentMethod string  `json:"payment_method"`
		Wallet        string  `json:"wallet"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if req.AmountUSD <= 0 {
		http.Error(w, "amount_usd required", 400)
		return
	}
	_, err := p4SQLDB.Exec(`
		UPDATE ir_incidents
		SET ransom_paid = true, ransom_amount_usd = $1, ransom_paid_at = NOW(),
		    is_ransomware = true, is_substantial = true, updated_at = NOW()
		WHERE incident_id = $2
	`, req.AmountUSD, req.IncidentID)
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}
	deadline := time.Now().Add(24 * time.Hour)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"recorded": true, "incident_id": req.IncidentID,
		"amount_usd": req.AmountUSD, "payment_method": req.PaymentMethod,
		"circia_24h_deadline": deadline,
		"action_required":     "Generate CIRCIA ransomware_payment report within 24 hours",
	})
}

// POST /api/p4/ir/incident/lessons
func handleIRIncidentLessons(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		IncidentID        string   `json:"incident_id"`
		LessonsLearned    string   `json:"lessons_learned"`
		RootCause         string   `json:"root_cause"`
		CorrectiveActions []string `json:"corrective_actions"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	actionsJSON, _ := json.Marshal(req.CorrectiveActions)
	_, err := p4SQLDB.Exec(`
		UPDATE ir_incidents
		SET lessons_learned = NULLIF($1,''),
		    root_cause = NULLIF($2,''),
		    corrective_actions = $3::jsonb,
		    updated_at = NOW()
		WHERE incident_id = $4
	`, req.LessonsLearned, req.RootCause, actionsJSON, req.IncidentID)
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"updated": true, "incident_id": req.IncidentID,
		"actions_count": len(req.CorrectiveActions),
	})
}

// GET /api/p4/circia/report/detail?uuid=...
func handleCIRCIAReportDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	uuid := r.URL.Query().Get("uuid")
	if uuid == "" {
		http.Error(w, "uuid required", 400)
		return
	}
	var reportType, status string
	var sector, cisaID, submittedBy, submittedTitle, submittedEmail, narrative sql.NullString
	var incidentDetected, deadline time.Time
	var submitted sql.NullTime
	var hoursElapsed, ransomPaid sql.NullFloat64
	var deadlineMet sql.NullBool
	var reportJSON []byte

	err := p4SQLDB.QueryRow(`
		SELECT report_type, status, ci_sector, incident_detected_at, deadline_at,
		       submitted_at, deadline_met, hours_elapsed, cisa_submission_id,
		       submitted_by_name, submitted_by_title, submitted_by_email,
		       narrative_description, ransom_paid_amount_usd, report_json
		FROM circia_reports WHERE report_uuid = $1
	`, uuid).Scan(&reportType, &status, &sector, &incidentDetected, &deadline,
		&submitted, &deadlineMet, &hoursElapsed, &cisaID,
		&submittedBy, &submittedTitle, &submittedEmail,
		&narrative, &ransomPaid, &reportJSON)
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)
		return
	}
	var fullJSON any
	_ = json.Unmarshal(reportJSON, &fullJSON)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"report_uuid":            uuid,
		"report_type":            reportType,
		"status":                 status,
		"ci_sector":              sector.String,
		"incident_detected_at":   incidentDetected,
		"deadline_at":            deadline,
		"submitted_at":           submitted.Time,
		"deadline_met":           deadlineMet.Bool,
		"hours_elapsed":          hoursElapsed.Float64,
		"cisa_submission_id":     cisaID.String,
		"submitted_by_name":      submittedBy.String,
		"submitted_by_title":     submittedTitle.String,
		"submitted_by_email":     submittedEmail.String,
		"narrative_description":  narrative.String,
		"ransom_paid_amount_usd": ransomPaid.Float64,
		"full_report":            fullJSON,
	})
}
