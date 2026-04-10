package store

import (
	"context"
	"fmt"
)

// InsertFindingsBatch inserts findings efficiently using pgx CopyFrom.
func (db *DB) InsertFindingsBatch(ctx context.Context, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	for _, f := range findings {
		_, err := db.pool.Exec(ctx,
			`INSERT INTO findings
			 (run_id, tenant_id, tool, severity, rule_id, message, path, line_num, cwe, cvss, fix_signal, raw)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			 ON CONFLICT DO NOTHING`,
			f.RunID, f.TenantID, f.Tool, f.Severity,
			f.RuleID, f.Message, f.Path, f.LineNum,
			f.CWE, f.CVSS, f.FixSignal, f.Raw)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", f.RuleID, err)
		}
	}
	return nil
}
