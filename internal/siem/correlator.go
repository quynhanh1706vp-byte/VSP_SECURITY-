// internal/siem/correlator.go
package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/store"
)

type BroadcastFn func([]byte)

type correlatorState struct {
	mu       sync.Mutex
	lastFire map[string]time.Time
}

func newCorrelatorState() *correlatorState {
	return &correlatorState{lastFire: make(map[string]time.Time)}
}

func (s *correlatorState) canFire(ruleID string, windowMin int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cooldown := time.Duration(windowMin*2) * time.Minute
	if cooldown < time.Minute {
		cooldown = time.Minute
	}
	last, seen := s.lastFire[ruleID]
	if !seen || time.Since(last) >= cooldown {
		s.lastFire[ruleID] = time.Now()
		return true
	}
	return false
}

func StartCorrelationEngine(ctx context.Context, db store.CorrelatorStore, broadcast BroadcastFn) {
	state := newCorrelatorState()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	log.Info().Msg("correlation engine started — interval: 30s")
	runCorrelationPass(ctx, db, broadcast, state)
	for {
		select {
		case <-ticker.C:
			runCorrelationPass(ctx, db, broadcast, state)
		case <-ctx.Done():
			log.Info().Msg("correlation engine stopped")
			return
		}
	}
}

func runCorrelationPass(ctx context.Context, db store.CorrelatorStore, broadcast BroadcastFn, state *correlatorState) {
	rows, err := db.ListAllEnabledRules(ctx)
	if err != nil {
		log.Error().Err(err).Msg("correlation: failed to load rules")
		return
	}
	defer rows.Close()

	type ruleRow struct {
		id, tenantID, name, severity, condExpr string
		sources                                 []string
		windowMin                               int
	}
	var rules []ruleRow
	for rows.Next() {
		var r ruleRow
		if err := rows.Scan(&r.id, &r.tenantID, &r.name,
			&r.sources, &r.windowMin, &r.severity, &r.condExpr); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	rows.Close()

	for _, rule := range rules {
		count, matchedHosts, err := countMatchingEvents(ctx, db, rule.tenantID, rule.sources, rule.windowMin, rule.condExpr)
		if err != nil {
			log.Error().Err(err).Str("rule", rule.name).Msg("correlation: query error")
			continue
		}
		threshold := extractThreshold(rule.condExpr)
		if count < threshold {
			continue
		}
		// DB dedup: skip nếu đã có incident cùng rule trong cooldown window
		var recentCount int
		recentCount, _ = db.CountRecentIncidents(ctx, rule.id, rule.windowMin*2)
		if recentCount > 0 {
			log.Debug().Str("rule", rule.name).Msg("correlation: dedup skip")
			continue
		}
		if !state.canFire(rule.id, rule.windowMin) {
			log.Debug().Str("rule", rule.name).Msg("correlation: cooldown active, skipping")
			continue
		}
		ruleID := rule.id
		sourceRefs, _ := json.Marshal(map[string]any{
			"rule_id":       rule.id,
			"event_count":   count,
			"window_min":    rule.windowMin,
			"matched_hosts": matchedHosts,
			"sources":       rule.sources,
			"fired_at":      time.Now().UTC(),
		})
		title := fmt.Sprintf("[AUTO] %s — %d events in %dmin window", rule.name, count, rule.windowMin)
		incID, err := db.CreateIncident(ctx, store.Incident{
			TenantID:   rule.tenantID,
			RuleID:     &ruleID,
			Title:      title,
			Severity:   rule.severity,
			SourceRefs: sourceRefs,
		})
		if err != nil {
			log.Error().Err(err).Str("rule", rule.name).Msg("correlation: failed to create incident")
			continue
		}
		db.UpdateCorrelationRuleHits(ctx, rule.id) //nolint:errcheck
		log.Info().
			Str("rule", rule.name).
			Str("incident_id", incID).
			Int("event_count", count).
			Str("severity", rule.severity).
			Msg("correlation: incident created")
		if broadcast != nil {
			msg, _ := json.Marshal(map[string]any{
				"type":        "incident_created",
				"incident_id": incID,
				"rule_id":     rule.id,
				"rule_name":   rule.name,
				"severity":    rule.severity,
				"title":       title,
				"event_count": count,
				"tenant_id":   rule.tenantID,
				"ts":          time.Now().UTC(),
			})
			broadcast(msg)
		}
		pbs, err := db.FindEnabledPlaybooks(ctx, rule.tenantID, "incident_created", rule.severity)
		if err == nil {
			for _, pb := range pbs {
				ctxJSON, _ := json.Marshal(map[string]any{
					"trigger":     "incident_created",
					"incident_id": incID,
					"rule_id":     rule.id,
					"severity":    rule.severity,
					"event_count": count,
				})
				runID, err := db.CreatePlaybookRun(ctx, pb.ID, rule.tenantID, "incident_created", ctxJSON)
				if err == nil {
					log.Info().Str("playbook", pb.Name).Str("run_id", runID).Msg("soar: auto-triggered on incident")
				}
			}
		}
	}
}

func countMatchingEvents(ctx context.Context, db store.CorrelatorStore, tenantID string, sources []string, windowMin int, condExpr string) (int, []string, error) {
	since := time.Now().Add(-time.Duration(windowMin) * time.Minute)
	extraWhere, args := buildConditionWhere(condExpr, tenantID, since)
	sourceFilter := ""
	if len(sources) > 0 && !(len(sources) == 1 && sources[0] == "*") {
		placeholders := make([]string, len(sources))
		for i, s := range sources {
			args = append(args, strings.ToLower(s))
			placeholders[i] = fmt.Sprintf("$%d", len(args))
		}
		sourceFilter = fmt.Sprintf(
			` AND (LOWER(process) = ANY(ARRAY[%s]) OR LOWER(facility) = ANY(ARRAY[%s]))`,
			strings.Join(placeholders, ","),
			strings.Join(placeholders, ","),
		)
	}
	q := fmt.Sprintf(`
		SELECT COUNT(*), COALESCE(array_agg(DISTINCT host) FILTER (WHERE host IS NOT NULL), '{}')
		FROM   log_events
		WHERE  tenant_id = $1
		  AND  ts >= $2
		%s%s`, extraWhere, sourceFilter)
	var count int
	var hosts []string
	count, hosts, err := db.QueryEventCount(ctx, q, args)
	return count, hosts, err
}

func buildConditionWhere(condExpr, tenantID string, since time.Time) (string, []any) {
	args := []any{tenantID, since}
	var clauses []string
	if condExpr == "" {
		return "", args
	}
	for _, part := range strings.Split(condExpr, " AND ") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		low := strings.ToLower(part)
		if strings.HasPrefix(low, "count") {
			continue
		}
		if strings.HasPrefix(low, "severity=") {
			val := strings.ToUpper(strings.SplitN(part, "=", 2)[1])
			args = append(args, val)
			clauses = append(clauses, fmt.Sprintf("UPPER(severity) = $%d", len(args)))
			continue
		}
		if strings.Contains(low, "severity>=") {
			val := strings.ToUpper(strings.SplitN(part, ">=", 2)[1])
			switch val {
			case "HIGH":
				clauses = append(clauses, `UPPER(severity) IN ('HIGH','CRITICAL')`)
			case "MEDIUM":
				clauses = append(clauses, `UPPER(severity) IN ('MEDIUM','HIGH','CRITICAL')`)
			default:
				args = append(args, val)
				clauses = append(clauses, fmt.Sprintf("UPPER(severity) = $%d", len(args)))
			}
			continue
		}
		if strings.Contains(part, "~") {
			kv := strings.SplitN(part, "~", 2)
			field := strings.TrimSpace(kv[0])
			val := "%" + strings.TrimSpace(kv[1]) + "%"
			args = append(args, val)
			clauses = append(clauses, fmt.Sprintf("%s ILIKE $%d", sanitizeField(field), len(args)))
			continue
		}
		if strings.HasPrefix(low, "host=") {
			val := strings.SplitN(part, "=", 2)[1]
			args = append(args, val)
			clauses = append(clauses, fmt.Sprintf("host = $%d", len(args)))
			continue
		}
		if strings.HasPrefix(low, "process=") {
			val := strings.SplitN(part, "=", 2)[1]
			args = append(args, strings.ToLower(val))
			clauses = append(clauses, fmt.Sprintf("LOWER(process) = $%d", len(args)))
			continue
		}
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			args = append(args, val)
			clauses = append(clauses, fmt.Sprintf("fields->>'%s' = $%d", sanitizeJSONKey(key), len(args)))
		}
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " AND " + strings.Join(clauses, " AND "), args
}

func extractThreshold(condExpr string) int {
	for _, part := range strings.Split(condExpr, " AND ") {
		part = strings.ToLower(strings.TrimSpace(part))
		if strings.HasPrefix(part, "count>=") {
			n := 0
			fmt.Sscanf(strings.TrimPrefix(part, "count>="), "%d", &n)
			if n > 0 {
				return n
			}
		}
		if strings.HasPrefix(part, "count>") {
			n := 0
			fmt.Sscanf(strings.TrimPrefix(part, "count>"), "%d", &n)
			if n > 0 {
				return n + 1
			}
		}
	}
	return 1
}

func sanitizeField(f string) string {
	switch strings.ToLower(f) {
	case "message", "msg":
		return "message"
	case "host":
		return "host"
	case "process":
		return "process"
	case "severity":
		return "severity"
	case "facility":
		return "facility"
	case "source_ip", "ip":
		return "source_ip"
	default:
		return "message"
	}
}

func sanitizeJSONKey(k string) string {
	var b strings.Builder
	for _, c := range k {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'  {
			b.WriteRune(c)
		}
	}
	return b.String()
}
