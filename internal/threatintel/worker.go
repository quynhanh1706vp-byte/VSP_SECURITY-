package threatintel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/store"
)

// Worker runs background threat intel enrichment
type Worker struct {
	client *Client
	db     *store.DB
}

func NewWorker(db *store.DB) *Worker {
	return &Worker{
		client: NewClient(),
		db:     db,
	}
}

// Start loads KEV and enriches CVE findings periodically
func (w *Worker) Start(ctx context.Context) {
	// Load KEV on startup
	if err := w.client.LoadKEV(ctx); err != nil {
		log.Warn().Err(err).Msg("ti: KEV load failed")
	}

	// Enrich existing CVE findings immediately
	go w.enrichPass(ctx)

	// Refresh KEV daily, enrich every 6h
	kevTicker := time.NewTicker(24 * time.Hour)
	enrichTicker := time.NewTicker(6 * time.Hour)
	defer kevTicker.Stop()
	defer enrichTicker.Stop()

	log.Info().Msg("ti: threat intel worker started")

	for {
		select {
		case <-ctx.Done():
			return
		case <-kevTicker.C:
			if err := w.client.LoadKEV(ctx); err != nil {
				log.Warn().Err(err).Msg("ti: KEV refresh failed")
			}
		case <-enrichTicker.C:
			go w.enrichPass(ctx)
		}
	}
}

// enrichPass finds CVE findings and enriches them
func (w *Worker) enrichPass(ctx context.Context) {
	// Get all tenants
	rows, err := w.db.Pool().Query(ctx, `SELECT id FROM tenants WHERE active=true`)
	if err != nil {
		log.Error().Err(err).Msg("ti: list tenants failed")
		return
	}
	defer rows.Close()

	var tenants []string
	for rows.Next() {
		var id string
		rows.Scan(&id) //nolint:errcheck
		tenants = append(tenants, id)
	}

	for _, tenantID := range tenants {
		w.enrichTenant(ctx, tenantID)
	}
}

func (w *Worker) enrichTenant(ctx context.Context, tenantID string) {
	// Find CVE findings not yet enriched (raw JSONB missing ti_enriched)
	rows, err := w.db.Pool().Query(ctx, `
		SELECT DISTINCT rule_id
		FROM findings
		WHERE tenant_id=$1
		  AND rule_id ILIKE 'CVE-%'
		  AND (raw IS NULL OR raw->>'ti_enriched' IS NULL)
		LIMIT 50`, tenantID)
	if err != nil {
		log.Error().Err(err).Msg("ti: query CVE findings failed")
		return
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var id string
		rows.Scan(&id) //nolint:errcheck
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			cveIDs = append(cveIDs, id)
		}
	}
	rows.Close()

	if len(cveIDs) == 0 {
		return
	}

	log.Info().Int("cves", len(cveIDs)).Str("tenant", tenantID[:8]).Msg("ti: enriching CVEs")

	// Batch enrich
	enriched := w.client.EnrichBatch(ctx, cveIDs)

	// Update findings with enrichment data
	for cveID, enr := range enriched {
		_, err := w.db.Pool().Exec(ctx, `
			UPDATE findings
			SET raw = COALESCE(raw, '{}'::jsonb) || $1::jsonb,
			    severity = CASE
			      WHEN $2 != '' AND $2 != severity THEN $2
			      ELSE severity
			    END
			WHERE tenant_id=$3 AND rule_id=$4`,
			enrichmentJSON(enr), enr.AdjustedSev, tenantID, cveID,
		)
		if err != nil {
			log.Warn().Err(err).Str("cve", cveID).Msg("ti: update failed")
		}
	}

	log.Info().Int("enriched", len(enriched)).Str("tenant", tenantID[:8]).Msg("ti: enrichment done")
}

func enrichmentJSON(enr *CVEEnrichment) string {
	return `{"ti_enriched":true,"cvss":` + fmtF(enr.CVSS) +
		`,"epss":` + fmtF(enr.EPSS) +
		`,"kev":` + fmtB(enr.KEV) +
		`,"risk_score":` + fmtF(enr.RiskScore) +
		`,"adjusted_severity":"` + enr.AdjustedSev + `"}`
}

func fmtF(f float64) string {
	return strings.TrimRight(strings.TrimRight(
		strings.Replace(strings.Replace(
			strings.Replace(fmt.Sprintf("%.4f", f), "+", "", -1),
			"e", "E", -1), " ", "", -1), "0"), ".")
}

func fmtB(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
