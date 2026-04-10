package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"time"
)

// ── P4 Database Persistence Layer ─────────────────────────
// Saves/loads P4 state to PostgreSQL so data survives restarts

var p4SQLDB *sql.DB

func initP4DB(db *sql.DB) {
	p4SQLDB = db
	if db == nil {
		log.Println("[P4-DB] No DB connection — using in-memory only")
		return
	}
	log.Println("[P4-DB] PostgreSQL persistence enabled")
	loadP4StateFromDB()
}

// ── Save ──────────────────────────────────────────────────

func saveZTStateToDB() {
	if p4SQLDB == nil {
		return
	}
	ztState.mu.RLock()
	pillarsJSON, _ := json.Marshal(ztState.Pillars)
	rulesJSON, _ := json.Marshal(ztState.SegRules)
	raspJSON, _ := json.Marshal(ztState.RASPEvents)
	coverJSON, _ := json.Marshal(ztState.RASPCoverage)
	polJSON, _ := json.Marshal(ztState.APIPolicies)
	sbomJSON, _ := json.Marshal(ztState.SBOM)
	overall := ztState.OverallScore
	p4r := ztState.P4Readiness
	p4a := ztState.P4Achieved
	ztState.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p4SQLDB.ExecContext(ctx, `
		INSERT INTO p4_zt_state (id, pillars, seg_rules, rasp_events, rasp_coverage, api_policies, sbom, overall_score, p4_readiness, p4_achieved, updated_at)
		VALUES ('main',$1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
		ON CONFLICT (id) DO UPDATE SET
			pillars=$1, seg_rules=$2, rasp_events=$3, rasp_coverage=$4,
			api_policies=$5, sbom=$6, overall_score=$7, p4_readiness=$8,
			p4_achieved=$9, updated_at=NOW()`,
		pillarsJSON, rulesJSON, raspJSON, coverJSON, polJSON, sbomJSON, overall, p4r, p4a)
	if err != nil {
		log.Printf("[P4-DB] saveZTState error: %v", err)
	}
}

func savePOAMToDB(item POAMItem) {
	if p4SQLDB == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p4SQLDB.ExecContext(ctx, `
		INSERT INTO p4_poam_items (id, system_id, weakness_name, control_id, severity, status, mitigation_plan, finding_id, scheduled_completion, closed_date, updated_at)
		VALUES ($1,'VSP-DOD-2025-001',$2,$3,$4,$5,$6,$7,$8,$9,NOW())
		ON CONFLICT (id) DO UPDATE SET
			status=$5, mitigation_plan=$6, closed_date=$9, updated_at=NOW()`,
		item.ID, item.WeaknessName, item.ControlID, item.Severity,
		item.Status, item.MitigationPlan, item.FindingID,
		item.ScheduledCompletion, item.ClosedDate)
	if err != nil {
		log.Printf("[P4-DB] savePOAM error: %v", err)
	}
}

func savePipelineRunToDB(run PipelineRun) {
	if p4SQLDB == nil {
		return
	}
	summaryJSON, _ := json.Marshal(run.Summary)
	testsJSON, _ := json.Marshal(run.Tests)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p4SQLDB.ExecContext(ctx, `
		INSERT INTO p4_pipeline_runs (id, trigger_type, trigger_ref, branch, status, summary, tests, started_at, completed_at, duration_sec)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (id) DO NOTHING`,
		run.ID, run.TriggerType, run.TriggerRef, run.Branch, run.Status,
		summaryJSON, testsJSON, run.StartedAt, run.CompletedAt, run.DurationSec)
	if err != nil {
		log.Printf("[P4-DB] savePipeline error: %v", err)
	}
}

// ── Load ──────────────────────────────────────────────────

func loadP4StateFromDB() {
	if p4SQLDB == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Load ZT state
	row := p4SQLDB.QueryRowContext(ctx, `SELECT pillars, seg_rules, rasp_coverage, api_policies, sbom, overall_score, p4_readiness, p4_achieved FROM p4_zt_state WHERE id='main'`)
	var pillarsJSON, rulesJSON, coverJSON, polJSON, sbomJSON []byte
	var overall, p4r int
	var p4a bool
	err := row.Scan(&pillarsJSON, &rulesJSON, &coverJSON, &polJSON, &sbomJSON, &overall, &p4r, &p4a)
	if err == nil {
		ztState.mu.Lock()
		if len(pillarsJSON) > 2 {
			json.Unmarshal(pillarsJSON, &ztState.Pillars)
		}
		if len(rulesJSON) > 2 {
			json.Unmarshal(rulesJSON, &ztState.SegRules)
		}
		if len(coverJSON) > 2 {
			json.Unmarshal(coverJSON, &ztState.RASPCoverage)
		}
		if len(polJSON) > 2 {
			json.Unmarshal(polJSON, &ztState.APIPolicies)
		}
		if len(sbomJSON) > 2 {
			json.Unmarshal(sbomJSON, &ztState.SBOM)
		}
		ztState.OverallScore = overall
		ztState.P4Readiness = p4r
		ztState.P4Achieved = p4a
		ztState.mu.Unlock()
		log.Printf("[P4-DB] ZT state loaded from DB — P4 Readiness: %d%%", p4r)
	} else {
		log.Println("[P4-DB] No ZT state in DB — using defaults")
	}

	// Load POAM items
	rows, err := p4SQLDB.QueryContext(ctx, `SELECT id, weakness_name, control_id, severity, status, mitigation_plan, finding_id, scheduled_completion, closed_date FROM p4_poam_items WHERE system_id='VSP-DOD-2025-001'`)
	if err == nil {
		defer rows.Close()
		rmfStore.mu.Lock()
		pkg := rmfStore.packages["VSP-DOD-2025-001"]
		if pkg != nil {
			existing := map[string]bool{}
			for _, p := range pkg.POAMItems {
				existing[p.ID] = true
			}
			for rows.Next() {
				var item POAMItem
				rows.Scan(&item.ID, &item.WeaknessName, &item.ControlID, &item.Severity, &item.Status, &item.MitigationPlan, &item.FindingID, &item.ScheduledCompletion, &item.ClosedDate)
				if !existing[item.ID] {
					pkg.POAMItems = append(pkg.POAMItems, item)
					existing[item.ID] = true
				}
			}
		}
		rmfStore.mu.Unlock()
		log.Println("[P4-DB] POAM items loaded from DB")
	}

	// Load recent pipeline runs
	pRows, err := p4SQLDB.QueryContext(ctx, `SELECT id, trigger_type, trigger_ref, branch, status, summary, started_at, completed_at, duration_sec FROM p4_pipeline_runs ORDER BY started_at DESC LIMIT 10`)
	if err == nil {
		defer pRows.Close()
		pipeStore.mu.Lock()
		existingRuns := map[string]bool{}
		for _, r := range pipeStore.Runs {
			existingRuns[r.ID] = true
		}
		for pRows.Next() {
			var run PipelineRun
			var summaryJSON []byte
			pRows.Scan(&run.ID, &run.TriggerType, &run.TriggerRef, &run.Branch, &run.Status, &summaryJSON, &run.StartedAt, &run.CompletedAt, &run.DurationSec)
			if !existingRuns[run.ID] {
				json.Unmarshal(summaryJSON, &run.Summary)
				pipeStore.Runs = append(pipeStore.Runs, run)
				existingRuns[run.ID] = true
			}
		}
		pipeStore.mu.Unlock()
		log.Println("[P4-DB] Pipeline runs loaded from DB")
	}

	// Auto-save current state to DB (seed if empty)
	go func() {
		time.Sleep(2 * time.Second)
		saveZTStateToDB()
		// Save default POAM items
		rmfStore.mu.RLock()
		pkg := rmfStore.packages["VSP-DOD-2025-001"]
		if pkg != nil {
			for _, item := range pkg.POAMItems {
				savePOAMToDB(item)
			}
		}
		rmfStore.mu.RUnlock()
		// Save pipeline runs
		pipeStore.mu.RLock()
		for _, run := range pipeStore.Runs {
			savePipelineRunToDB(run)
		}
		pipeStore.mu.RUnlock()
		log.Println("[P4-DB] Initial state saved to DB")
	}()
}
