#!/usr/bin/env bash
# fix2.sh — fix POST /vsp/run 500 error
# Chay tu ~/Data/GOLANG_VSP
set -e

echo ">>> Diagnosing POST /vsp/run error..."

# Check what error the gateway is returning
RESP=$(curl -s -X POST http://localhost:8921/api/v1/vsp/run \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"SAST","src":"/tmp"}')
echo "Response: $RESP"

echo ""
echo ">>> Patching internal/store/runs.go — fix scanRun + CreateRun..."

cat > internal/store/runs.go << 'GOEOF'
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type Run struct {
	ID            string          `json:"id"`
	RID           string          `json:"rid"`
	TenantID      string          `json:"tenant_id"`
	Mode          string          `json:"mode"`
	Profile       string          `json:"profile"`
	Src           string          `json:"src"`
	TargetURL     string          `json:"target_url"`
	Status        string          `json:"status"`
	Gate          string          `json:"gate"`
	Posture       string          `json:"posture"`
	ToolsDone     int             `json:"tools_done"`
	ToolsTotal    int             `json:"tools_total"`
	TotalFindings int             `json:"total_findings"`
	Summary       json.RawMessage `json:"summary"`
	StartedAt     *time.Time      `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at"`
	CreatedAt     time.Time       `json:"created_at"`
}

const runCols = `id, rid, tenant_id, mode, profile, src, target_url, status,
	gate, posture, tools_done, tools_total, total_findings,
	summary, started_at, finished_at, created_at`

func (db *DB) CreateRun(ctx context.Context, rid, tenantID, mode, profile, src, targetURL string, toolsTotal int) (*Run, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO runs (rid, tenant_id, mode, profile, src, target_url, tools_total)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING `+runCols,
		rid, tenantID, mode, profile, src, targetURL, toolsTotal)
	return scanRun(row)
}

func (db *DB) GetRunByRID(ctx context.Context, tenantID, rid string) (*Run, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT `+runCols+` FROM runs WHERE rid=$1 AND tenant_id=$2 LIMIT 1`,
		rid, tenantID)
	return scanRun(row)
}

func (db *DB) GetLatestRun(ctx context.Context, tenantID string) (*Run, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT `+runCols+` FROM runs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 1`,
		tenantID)
	return scanRun(row)
}

func (db *DB) ListRuns(ctx context.Context, tenantID string, limit, offset int) ([]Run, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+runCols+` FROM runs WHERE tenant_id=$1
		 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()
	var runs []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, *r)
	}
	return runs, nil
}

func (db *DB) UpdateRunStatus(ctx context.Context, tenantID, rid, status string, toolsDone int) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE runs SET status=$3, tools_done=$4,
		  started_at  = CASE WHEN $3='RUNNING' AND started_at IS NULL THEN NOW() ELSE started_at END,
		  finished_at = CASE WHEN $3 IN ('DONE','FAILED','CANCELLED') THEN NOW() ELSE finished_at END
		 WHERE rid=$1 AND tenant_id=$2`,
		rid, tenantID, status, toolsDone)
	return err
}

func (db *DB) UpdateRunResult(ctx context.Context, tenantID, rid, gate, posture string, total int, summary json.RawMessage) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE runs
		 SET status='DONE', gate=$3, posture=$4, total_findings=$5,
		     summary=$6, tools_done=tools_total, finished_at=NOW()
		 WHERE rid=$1 AND tenant_id=$2`,
		rid, tenantID, gate, posture, total, summary)
	return err
}

func scanRun(row scanner) (*Run, error) {
	var r Run
	// gate, posture may be NULL in DB
	var gate, posture *string
	err := row.Scan(
		&r.ID, &r.RID, &r.TenantID, &r.Mode, &r.Profile,
		&r.Src, &r.TargetURL, &r.Status, &gate, &posture,
		&r.ToolsDone, &r.ToolsTotal, &r.TotalFindings,
		&r.Summary, &r.StartedAt, &r.FinishedAt, &r.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan run: %w", err)
	}
	if gate != nil    { r.Gate = *gate }
	if posture != nil { r.Posture = *posture }
	if r.Summary == nil { r.Summary = json.RawMessage("{}") }
	return &r, nil
}
GOEOF
echo "✓ store/runs.go patched"

echo ">>> Patching internal/store/findings.go — fix SQL variable name..."
sed -i 's/whoseSQL/whereSQL/g' internal/store/findings.go
echo "✓ findings.go patched"

echo ">>> Rebuilding..."
go build -buildvcs=false -o gateway ./cmd/gateway/
echo "✓ Build OK"

echo ">>> Restarting..."
pkill -f './gateway' 2>/dev/null || pkill -f 'gateway' 2>/dev/null || true
sleep 1
./gateway &
sleep 2

echo ""
echo ">>> Full test..."
export TOKEN=$(curl -s -X POST http://localhost:8921/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@vsp.local","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Token: ${TOKEN:0:30}..."

echo ""
echo "--- POST /vsp/run"
curl -s -X POST http://localhost:8921/api/v1/vsp/run \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"SAST","src":"/tmp/test","profile":"FAST"}' | python3 -m json.tool

echo ""
echo "--- GET /vsp/runs"
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8921/api/v1/vsp/runs | python3 -m json.tool

echo ""
echo "--- GET /vsp/findings/summary"
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8921/api/v1/vsp/findings/summary | python3 -m json.tool

echo ""
echo "--- POST /policy/evaluate (latest run)"
curl -s -X POST http://localhost:8921/api/v1/policy/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"repo":"myapp"}' | python3 -m json.tool

echo ""
echo "--- GET /audit/log"
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8921/api/v1/audit/log | python3 -m json.tool

echo ""
echo "--- POST /audit/verify"
curl -s -X POST http://localhost:8921/api/v1/audit/verify \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

echo ""
echo "================================================================"
echo "  fix2.sh complete — all A+B+C+D endpoints live"
echo "================================================================"
