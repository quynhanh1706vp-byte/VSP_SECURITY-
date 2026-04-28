//go:build integration

package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vsp/platform/internal/testutil"
)

func TestAutoResolveOrphans_HappyPath(t *testing.T) {
	db := testutil.TestDB(t)
	ctx := context.Background()

	var tenantID string
	require.NoError(t, db.Pool().QueryRow(ctx,
		`INSERT INTO tenants(slug,name,plan) VALUES($1,$2,'enterprise') RETURNING id`,
		fmt.Sprintf("ar-%d", time.Now().UnixNano()), "AutoResolve Test",
	).Scan(&tenantID))
	defer testutil.CleanupTenant(t, db, tenantID)

	// Run #1 with finding A
	var run1ID, findA string
	require.NoError(t, db.Pool().QueryRow(ctx,
		`INSERT INTO runs(tenant_id,mode,profile,status) VALUES($1,'SAST','FAST','completed') RETURNING id`,
		tenantID,
	).Scan(&run1ID))
	require.NoError(t, db.Pool().QueryRow(ctx,
		`INSERT INTO findings(tenant_id,run_id,tool,rule_id,severity,message)
		 VALUES($1,$2,'gosec','G404','HIGH','weak rng') RETURNING id`,
		tenantID, run1ID,
	).Scan(&findA))

	_, err := db.Pool().Exec(ctx,
		`INSERT INTO remediations(tenant_id,finding_id,status,priority)
		 VALUES($1,$2,'open','P2')`,
		tenantID, findA)
	require.NoError(t, err)

	// Run #2 (newer) with different finding — A is orphan
	var run2ID string
	require.NoError(t, db.Pool().QueryRow(ctx,
		`INSERT INTO runs(tenant_id,mode,profile,status,created_at)
		 VALUES($1,'SAST','FAST','completed',NOW() + INTERVAL '1 minute') RETURNING id`,
		tenantID,
	).Scan(&run2ID))
	_, err = db.Pool().Exec(ctx,
		`INSERT INTO findings(tenant_id,run_id,tool,rule_id,severity,message)
		 VALUES($1,$2,'gosec','G505','MEDIUM','weak crypto')`,
		tenantID, run2ID)
	require.NoError(t, err)

	res, err := db.AutoResolveOrphans(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Resolved)
	assert.Equal(t, run2ID, res.RunID)

	var status string
	require.NoError(t, db.Pool().QueryRow(ctx,
		`SELECT status FROM remediations WHERE finding_id=$1`, findA,
	).Scan(&status))
	assert.Equal(t, "resolved", status)

	// Idempotency
	res2, err := db.AutoResolveOrphans(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, 0, res2.Resolved)
}

func TestAutoResolveOrphans_NoRuns_ReturnsError(t *testing.T) {
	db := testutil.TestDB(t)
	ctx := context.Background()

	var tenantID string
	require.NoError(t, db.Pool().QueryRow(ctx,
		`INSERT INTO tenants(slug,name,plan) VALUES($1,$2,'enterprise') RETURNING id`,
		fmt.Sprintf("ar3-%d", time.Now().UnixNano()), "AutoResolve Empty Test",
	).Scan(&tenantID))
	defer testutil.CleanupTenant(t, db, tenantID)

	_, err := db.AutoResolveOrphans(ctx, tenantID)
	assert.Error(t, err, "should error when no completed runs exist")
}
