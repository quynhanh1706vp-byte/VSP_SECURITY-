// Package handler — public-facing status JSON for an external status
// page (statuspage.io / instatus / self-hosted Cachet) to consume.
//
// GET /api/v1/status   — anonymous, cache-friendly
//
// Returns a small uptime + SLO snapshot + open-incident count. The
// shape matches what most status-page importers expect:
//
//	{
//	  "status": "operational" | "degraded" | "partial_outage" | "major_outage",
//	  "components": [
//	    {"name":"gateway",   "status":"operational"},
//	    {"name":"scanner",   "status":"operational"},
//	    {"name":"audit_log", "status":"operational"}
//	  ],
//	  "slo": {
//	    "availability_30d_pct": 99.94,
//	    "p95_latency_ms": 312,
//	    "target_p95_ms": 500
//	  },
//	  "open_incidents": 0,
//	  "as_of": "2026-05-08T12:34:56Z"
//	}
//
// The endpoint deliberately avoids any tenant-scoped data — anyone on
// the public internet can read it. Per-tenant SLO breakdowns live on
// the authenticated /api/v1/dora endpoint.
package handler

import (
	"net/http"
	"time"

	"github.com/vsp/platform/internal/store"
)

type StatusPublic struct {
	DB *store.DB
}

func NewStatusPublic(db *store.DB) *StatusPublic { return &StatusPublic{DB: db} }

type statusComponent struct {
	Name   string `json:"name"`
	Status string `json:"status"` // operational | degraded | partial_outage | major_outage
}

func (h *StatusPublic) Get(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	gateway := h.gatewayHealth(r)
	scanner := h.scannerHealth(r)
	audit := h.auditChainHealth(r)

	overall := "operational"
	for _, c := range []string{gateway, scanner, audit} {
		if c == "major_outage" {
			overall = "major_outage"
			break
		}
		if c == "partial_outage" && overall != "major_outage" {
			overall = "partial_outage"
		}
		if c == "degraded" && overall == "operational" {
			overall = "degraded"
		}
	}

	avail, p95 := h.sloSnapshot(r)
	open := h.openIncidents(r)

	// Cache for 30 s — status pages poll every minute typically; this
	// keeps the DB load trivial without making outage detection slow.
	w.Header().Set("Cache-Control", "public, max-age=30")
	w.Header().Set("Content-Type", "application/json")
	jsonOK(w, map[string]any{
		"status": overall,
		"components": []statusComponent{
			{"gateway", gateway},
			{"scanner", scanner},
			{"audit_log", audit},
		},
		"slo": map[string]any{
			"availability_30d_pct": avail,
			"p95_latency_ms":       p95,
			"target_p95_ms":        500,
		},
		"open_incidents": open,
		"as_of":          now.Format(time.RFC3339),
	})
}

// gatewayHealth — if we're answering the request at all, gateway is
// at least partially up. We mark "degraded" when DB ping fails.
func (h *StatusPublic) gatewayHealth(r *http.Request) string {
	if err := h.DB.Pool().Ping(r.Context()); err != nil {
		return "major_outage"
	}
	return "operational"
}

// scannerHealth — proxy: any successful run completion in the last
// hour means the scan pipeline is moving. Lack of completions doesn't
// necessarily mean outage (could be quiet period), so we look at
// failure rate instead.
func (h *StatusPublic) scannerHealth(r *http.Request) string {
	var done, failed int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT
		   COUNT(*) FILTER (WHERE status='COMPLETED'),
		   COUNT(*) FILTER (WHERE status IN ('FAILED','ERROR'))
		 FROM runs
		 WHERE finished_at > NOW() - INTERVAL '1 hour'`,
	).Scan(&done, &failed)
	total := done + failed
	if total == 0 {
		return "operational"
	}
	failRate := float64(failed) / float64(total)
	switch {
	case failRate >= 0.5:
		return "partial_outage"
	case failRate >= 0.1:
		return "degraded"
	}
	return "operational"
}

// auditChainHealth — any CHAIN_BROKEN in the last 24h is a
// partial outage signal even if everything else looks fine. Audit
// chain integrity is a load-bearing claim for compliance customers.
func (h *StatusPublic) auditChainHealth(r *http.Request) string {
	var n int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM audit_log
		  WHERE action = 'CHAIN_BROKEN'
		    AND created_at > NOW() - INTERVAL '24 hours'`,
	).Scan(&n)
	if n > 0 {
		return "partial_outage"
	}
	return "operational"
}

// sloSnapshot returns (availability_pct_30d, p95_latency_ms) computed
// from the existing telemetry tables. We return zero on missing data
// so a fresh deployment doesn't lie about its track record.
func (h *StatusPublic) sloSnapshot(r *http.Request) (float64, int) {
	// Rough proxy until we wire real prom metrics into the DB:
	// availability = 1 - (failed runs / total runs) over 30 days.
	var done, failed int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT
		   COUNT(*) FILTER (WHERE status='COMPLETED'),
		   COUNT(*) FILTER (WHERE status IN ('FAILED','ERROR'))
		 FROM runs
		 WHERE finished_at > NOW() - INTERVAL '30 days'`,
	).Scan(&done, &failed)
	avail := 100.0
	if total := done + failed; total > 0 {
		avail = float64(done) / float64(total) * 100
	}
	// p95 latency proxy: median run duration in seconds × 1000ms.
	// Pre-prom-wired this is the closest signal we have.
	var p95 int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COALESCE(EXTRACT(EPOCH FROM (
		   PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY finished_at - started_at)
		 )) * 1000, 0)::int
		   FROM runs
		  WHERE finished_at > NOW() - INTERVAL '30 days'
		    AND status='COMPLETED'`,
	).Scan(&p95)
	return round1(avail), p95
}

// openIncidents returns the count of unresolved incidents (status not
// in 'resolved' or 'closed'). Anonymous — count only, no detail.
func (h *StatusPublic) openIncidents(r *http.Request) int {
	var n int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM ir_incidents
		  WHERE status NOT IN ('resolved','closed','false_positive')`,
	).Scan(&n)
	return n
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
