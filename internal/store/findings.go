package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Finding struct {
	ID        string          `json:"id"`
	RunID     string          `json:"run_id"`
	TenantID  string          `json:"tenant_id"`
	Tool      string          `json:"tool"`
	Severity  string          `json:"severity"`
	RuleID    string          `json:"rule_id"`
	Message   string          `json:"message"`
	Path      string          `json:"path"`
	LineNum   int             `json:"line"`
	CWE       string          `json:"cwe"`
	FixSignal string          `json:"fix_signal"`
	Raw       json.RawMessage `json:"raw,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type FindingFilter struct {
	RunID    string
	Severity string
	Tool     string
	Search   string // message/rule/path substring
	Limit    int
	Offset   int
}

func (db *DB) InsertFindings(ctx context.Context, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	// batch insert
	for _, f := range findings {
		_, err := db.pool.Exec(ctx,
			`INSERT INTO findings
			 (run_id, tenant_id, tool, severity, rule_id, message, path, line_num, cwe, fix_signal, raw)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			f.RunID, f.TenantID, f.Tool, f.Severity, f.RuleID,
			f.Message, f.Path, f.LineNum, f.CWE, f.FixSignal, f.Raw)
		if err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}
	return nil
}

func (db *DB) ListFindings(ctx context.Context, tenantID string, f FindingFilter) ([]Finding, int64, error) {
	if f.Limit == 0  { f.Limit = 50   }
	if f.Limit > 2000 { f.Limit = 2000 } // hard cap tại store layer

	where := []string{"tenant_id = $1"}
	args  := []any{tenantID}
	i := 2

	if f.RunID != "" {
		where = append(where, fmt.Sprintf("run_id = $%d", i))
		args = append(args, f.RunID); i++
	}
	if f.Severity != "" {
		where = append(where, fmt.Sprintf("severity = $%d", i))
		args = append(args, strings.ToUpper(f.Severity)); i++
	}
	if f.Tool != "" {
		where = append(where, fmt.Sprintf("tool = $%d", i))
		args = append(args, f.Tool); i++
	}
	if f.Search != "" {
		// Defense in depth: cap search length tại store layer
		s := f.Search
		if len(s) > 200 { s = s[:200] }
		where = append(where, fmt.Sprintf("(message ILIKE $%d OR rule_id ILIKE $%d OR path ILIKE $%d)", i, i, i))
		args = append(args, "%"+s+"%"); i++
	}

	whereSQL := strings.Join(where, " AND ")

	var total int64
	db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM findings WHERE "+whereSQL, args...).Scan(&total)

	args = append(args, f.Limit, f.Offset)
	rows, err := db.pool.Query(ctx,
		fmt.Sprintf(`SELECT id, run_id, tenant_id, tool, severity, rule_id,
		             message, path, line_num, cwe, fix_signal, created_at
		             FROM findings WHERE %s
		             ORDER BY
		               CASE severity
		                 WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
		                 WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4
		                 ELSE 5
		               END,
		               created_at DESC
		             LIMIT $%d OFFSET $%d`, whereSQL, i, i+1),
		args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var result []Finding
	for rows.Next() {
		var fn Finding
		if err := rows.Scan(&fn.ID, &fn.RunID, &fn.TenantID, &fn.Tool,
			&fn.Severity, &fn.RuleID, &fn.Message, &fn.Path,
			&fn.LineNum, &fn.CWE, &fn.FixSignal, &fn.CreatedAt); err != nil {
			return nil, 0, err
		}
		result = append(result, fn)
	}
	return result, total, nil
}

type FindingSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

func (db *DB) FindingsSummary(ctx context.Context, tenantID, runID string) (*FindingSummary, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT severity, COUNT(*) FROM findings
		 WHERE tenant_id=$1 AND ($2='' OR run_id::text=$2)
		 GROUP BY severity`,
		tenantID, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	s := &FindingSummary{}
	for rows.Next() {
		var sev string; var cnt int
		rows.Scan(&sev, &cnt)
		switch sev {
		case "CRITICAL": s.Critical = cnt
		case "HIGH":     s.High = cnt
		case "MEDIUM":   s.Medium = cnt
		case "LOW":      s.Low = cnt
		default:         s.Info += cnt
		}
		s.Total += cnt
	}
	return s, nil
}
