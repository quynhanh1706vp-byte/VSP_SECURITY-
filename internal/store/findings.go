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
	CVSS      float64         `json:"cvss"`
	FixSignal string          `json:"fix_signal"`
	Raw       json.RawMessage `json:"raw,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	Status    string          `json:"status"`
	// FirstSeen / LastSeen come from a per-fingerprint aggregate
	// (MIN/MAX(created_at) WHERE fingerprint=f.fingerprint AND
	// tenant_id=f.tenant_id). They tell the operator whether this
	// finding has been seen across multiple runs, even if those runs
	// were weeks apart. Both are nullable in JSON because pre-2026-05-12
	// callers that didn't request the join would receive null — the FE
	// detail modal falls back to created_at in that case.
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

type FindingFilter struct {
	RunID    string
	Severity string
	Tool     string
	Search   string // message/rule/path substring
	Limit    int
	Offset   int
}

func (db *DB) ListFindings(ctx context.Context, tenantID string, f FindingFilter) ([]Finding, int64, error) {
	if f.Limit == 0 {
		f.Limit = 50
	}
	if f.Limit > 2000 {
		f.Limit = 2000
	} // hard cap tại store layer

	where := []string{"f.tenant_id = $1"}
	args := []any{tenantID}
	i := 2

	if f.RunID != "" {
		where = append(where, fmt.Sprintf("f.run_id = $%d", i))
		args = append(args, f.RunID)
		i++
	}
	if f.Severity != "" {
		where = append(where, fmt.Sprintf("f.severity = $%d", i))
		args = append(args, strings.ToUpper(f.Severity))
		i++
	}
	if f.Tool != "" {
		where = append(where, fmt.Sprintf("f.tool = $%d", i))
		args = append(args, f.Tool)
		i++
	}
	if f.Search != "" {
		// Defense in depth: cap search length tại store layer
		s := f.Search
		if len(s) > 200 {
			s = s[:200]
		}
		// Use GIN index via to_tsvector for performance on large datasets
		// Fallback to ILIKE for exact substring matching (covered by idx_findings_search)
		where = append(where, fmt.Sprintf("(f.message ILIKE $%d OR f.rule_id ILIKE $%d OR f.path ILIKE $%d)", i, i, i))
		args = append(args, "%"+s+"%")
		i++
	}

	whereSQL := strings.Join(where, " AND ")

	var total int64
	// whereSQL chỉ chứa $N placeholders — không có user input trực tiếp
	db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM findings f LEFT JOIN remediations r ON r.finding_id=f.id AND r.tenant_id=f.tenant_id WHERE "+whereSQL, args...).Scan(&total) //nolint:errcheck

	args = append(args, f.Limit, f.Offset)
	// first_seen / last_seen come from a per-fingerprint aggregate
	// scoped to the tenant. The (tenant_id, fingerprint) index added by
	// migration 020 makes each correlated subquery a constant-time
	// index lookup, so worst-case 2 × LIMIT extra index hits — cheap
	// even at LIMIT=2000.
	rows, err := db.pool.Query(ctx,
		fmt.Sprintf(`SELECT f.id, f.run_id, f.tenant_id, f.tool, f.severity, f.rule_id,
		             f.message, f.path, f.line_num, f.cwe, f.cvss, f.fix_signal, f.created_at,
		             COALESCE(r.status::text, 'open') as remediation_status,
		             (SELECT MIN(ff.created_at) FROM findings ff
		              WHERE ff.tenant_id = f.tenant_id AND ff.fingerprint = f.fingerprint) AS first_seen,
		             (SELECT MAX(ff.created_at) FROM findings ff
		              WHERE ff.tenant_id = f.tenant_id AND ff.fingerprint = f.fingerprint) AS last_seen
		             FROM findings f
		             LEFT JOIN remediations r ON r.finding_id=f.id AND r.tenant_id=f.tenant_id
		             WHERE %s
		             ORDER BY
		               CASE f.severity
		                 WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
		                 WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4
		                 ELSE 5
		               END,
		               f.created_at DESC
		             LIMIT $%d OFFSET $%d`, whereSQL, i, i+1),
		args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var result []Finding
	for rows.Next() {
		var fn Finding
		var ruleID, message, fpath, cwe, fixSignal *string
		var cvss *float64
		var lineNum *int
		var remStatus *string
		var firstSeen, lastSeen *time.Time
		if err := rows.Scan(&fn.ID, &fn.RunID, &fn.TenantID, &fn.Tool,
			&fn.Severity, &ruleID, &message, &fpath,
			&lineNum, &cwe, &cvss, &fixSignal, &fn.CreatedAt, &remStatus,
			&firstSeen, &lastSeen); err != nil {
			return nil, 0, err
		}
		fn.FirstSeen = firstSeen
		fn.LastSeen = lastSeen
		if ruleID != nil {
			fn.RuleID = *ruleID
		}
		if message != nil {
			fn.Message = *message
		}
		if fpath != nil {
			fn.Path = *fpath
		}
		if cwe != nil {
			fn.CWE = *cwe
		}
		if cvss != nil {
			fn.CVSS = *cvss
		}
		if fixSignal != nil {
			fn.FixSignal = *fixSignal
		}
		if lineNum != nil {
			fn.LineNum = *lineNum
		}
		if remStatus != nil {
			fn.Status = *remStatus
		} else {
			fn.Status = "open"
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
		var sev string
		var cnt int
		_ = rows.Scan(&sev, &cnt)
		switch sev {
		case "CRITICAL":
			s.Critical = cnt
		case "HIGH":
			s.High = cnt
		case "MEDIUM":
			s.Medium = cnt
		case "LOW":
			s.Low = cnt
		default:
			s.Info += cnt
		}
		s.Total += cnt
	}
	return s, nil
}
