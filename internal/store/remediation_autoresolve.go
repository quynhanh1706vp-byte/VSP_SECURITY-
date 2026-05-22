// File: internal/store/remediation_autoresolve.go
//
// AutoResolveOrphans marks remediations as 'resolved' when their finding's
// fingerprint no longer appears in a NEWER complete-and-non-empty run of the
// SAME mode for that tenant.
//
// Safety guards (defense-in-depth against false-positive resolves):
//   1. Newer run.status = 'DONE'                 — execution finished
//   2. Newer run.tools_done = run.tools_total    — all scanners ran (no partial)
//   3. Newer run has > 0 findings persisted      — not an empty/corrupt scan
//   4. Same mode as old run                      — SAST≠IAC≠DAST etc.
//   5. Newer run.created_at > old run.created_at — strictly newer
//
// Schema-aware:
//   - runs.status uppercase: 'DONE' for success, 'FAILED', 'QUEUED'
//   - findings.fingerprint = generated md5(tool|rule_id|path|line)
//   - findings.run_id FK runs.id; remediations.finding_id FK findings.id
//
// Idempotent. Safe to call repeatedly.

package store

import (
	"context"
	"fmt"
	"time"
)

// AutoResolveResult — return shape for the API
type AutoResolveResult struct {
	Resolved   int      `json:"resolved"`
	Checked    int      `json:"checked"`              // open remediations evaluated
	Skipped    int      `json:"skipped_no_newer_run"` // no newer complete-and-non-empty run of same mode
	FindingIDs []string `json:"finding_ids,omitempty"`
}

// AutoResolveOrphans closes remediations whose finding's fingerprint is missing
// from the newest complete-and-non-empty DONE run of the same mode.
func (db *DB) AutoResolveOrphans(ctx context.Context, tenantID string) (*AutoResolveResult, error) {
	const stmt = `
WITH candidates AS (
	SELECT
		r.id            AS rem_id,
		r.finding_id    AS finding_id,
		f.fingerprint   AS fp,
		f.run_id        AS old_run_id,
		old_run.mode    AS mode,
		old_run.created_at AS old_created_at
	FROM remediations r
	JOIN findings f      ON f.id = r.finding_id
	JOIN runs     old_run ON old_run.id = f.run_id
	WHERE r.tenant_id = $1
	  AND r.status = 'open'
),
newer_runs AS (
	SELECT
		c.rem_id,
		c.finding_id,
		c.fp,
		c.mode,
		(
			SELECT nr.id
			FROM runs nr
			WHERE nr.tenant_id = $1
			  AND nr.status = 'DONE'
			  AND nr.mode = c.mode
			  AND nr.created_at > c.old_created_at
			  -- GUARD 1: all scanners ran (no partial completion)
			  AND nr.tools_done = nr.tools_total
			  AND nr.tools_total > 0
			  -- GUARD 2: scan actually persisted findings (not empty/corrupt)
			  AND EXISTS (SELECT 1 FROM findings nf WHERE nf.run_id = nr.id LIMIT 1)
			ORDER BY nr.created_at DESC
			LIMIT 1
		) AS new_run_id
	FROM candidates c
),
to_resolve AS (
	SELECT nr.rem_id, nr.finding_id
	FROM newer_runs nr
	WHERE nr.new_run_id IS NOT NULL
	  AND NOT EXISTS (
	      SELECT 1 FROM findings f1
	      WHERE f1.run_id = nr.new_run_id
	        AND f1.fingerprint = nr.fp
	  )
),
updated AS (
	UPDATE remediations
	   SET status      = 'resolved',
	       resolved_at = NOW(),
	       updated_at  = NOW(),
	       notes       = CASE
	                       WHEN notes = '' THEN $2
	                       ELSE notes || E'\n' || $2
	                     END
	 WHERE id IN (SELECT rem_id FROM to_resolve)
	RETURNING finding_id
)
SELECT
	(SELECT COUNT(*) FROM candidates)                              AS checked,
	(SELECT COUNT(*) FROM newer_runs WHERE new_run_id IS NULL)     AS skipped,
	(SELECT COUNT(*) FROM updated)                                 AS resolved,
	COALESCE(ARRAY(SELECT finding_id::text FROM updated), '{}')    AS resolved_ids
`

	noteSuffix := fmt.Sprintf("[auto-resolved: fingerprint absent in newer complete same-mode run @ %s]",
		time.Now().UTC().Format(time.RFC3339))

	var (
		checked, skipped, resolved int
		resolvedIDs                []string
	)
	err := db.Pool().QueryRow(ctx, stmt, tenantID, noteSuffix).
		Scan(&checked, &skipped, &resolved, &resolvedIDs)
	if err != nil {
		return nil, fmt.Errorf("auto-resolve query: %w", err)
	}

	return &AutoResolveResult{
		Resolved:   resolved,
		Checked:    checked,
		Skipped:    skipped,
		FindingIDs: resolvedIDs,
	}, nil
}
