package soar

import (
	"context"
	"encoding/json"
	"strings"
)

// ─────────────────────────────────────────────────────────────────
// Legacy compat — translates old-style step configs into engine-friendly
// behavior, so the 4 existing playbooks (created before DAG migration)
// keep working.
//
// Old format example (from "Gate FAIL auto-response"):
//   {"Type":"enrich","Config":"source: NVD,OSV\nfields: [cvss,epss,kev]"}
//
// We parse the YAML-ish Config string into a map[string]string, then
// dispatch based on Type.
// ─────────────────────────────────────────────────────────────────

// parseLegacyConfig parses the simple "key: value" YAML-ish format used by
// legacy playbooks. It does NOT support full YAML — just flat key/value
// pairs separated by newlines or commas. This matches the format actually
// stored in the 4 existing playbooks.
func parseLegacyConfig(raw string) map[string]string {
	out := make(map[string]string)
	if raw == "" {
		return out
	}
	// Split by lines (\n or literal \n)
	lines := strings.Split(strings.ReplaceAll(raw, "\\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Split on first ":"
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		// Strip array notation [a,b,c]
		v = strings.Trim(v, "[]")
		if k != "" {
			out[k] = v
		}
	}
	return out
}

// legacyConditionToJS converts a legacy condition like
// "gate=FAIL AND severity IN [CRITICAL,HIGH]"
// into a JS expression compatible with the sandbox.
//
// Coverage (best-effort, not full SQL):
//   - X=Y         → ctx.X === "Y"
//   - X IN [A,B]  → ["A","B"].indexOf(ctx.X) >= 0
//   - AND / OR    → && / ||
func legacyConditionToJS(raw string) string {
	if raw == "" {
		return "false"
	}
	s := raw
	// Tokenize by replacing operators
	s = strings.ReplaceAll(s, " AND ", " && ")
	s = strings.ReplaceAll(s, " OR ", " || ")
	s = strings.ReplaceAll(s, " and ", " && ")
	s = strings.ReplaceAll(s, " or ", " || ")

	// Handle "X IN [A,B,C]" → ["A","B","C"].indexOf(ctx.X) >= 0
	for {
		idx := strings.Index(s, " IN [")
		if idx < 0 {
			idx = strings.Index(s, " in [")
			if idx < 0 {
				break
			}
		}
		// Find matching ]
		end := strings.Index(s[idx:], "]")
		if end < 0 {
			break
		}
		end += idx
		// Extract var name (token before " IN ")
		varStart := strings.LastIndexAny(s[:idx], " \t\n(")
		varName := strings.TrimSpace(s[varStart+1 : idx])
		listRaw := s[idx+5 : end]
		items := strings.Split(listRaw, ",")
		quoted := make([]string, 0, len(items))
		for _, it := range items {
			it = strings.TrimSpace(it)
			quoted = append(quoted, "\""+it+"\"")
		}
		replacement := "[" + strings.Join(quoted, ",") + "].indexOf(ctx." + varName + ") >= 0"
		s = s[:varStart+1] + replacement + s[end+1:]
	}

	// Handle "X=Y" → ctx.X === "Y"  (skip if already has === or has < > )
	// This is naive; handles single-equal comparisons without quotes.
	if !strings.Contains(s, "===") && strings.Contains(s, "=") {
		// Walk tokens
		tokens := strings.Fields(s)
		var out []string
		for _, tok := range tokens {
			if i := strings.Index(tok, "="); i > 0 && i < len(tok)-1 &&
				tok[i+1] != '=' && tok[i-1] != '!' && tok[i-1] != '>' && tok[i-1] != '<' {
				k := tok[:i]
				v := tok[i+1:]
				out = append(out, "ctx."+k+" === \""+v+"\"")
				continue
			}
			out = append(out, tok)
		}
		s = strings.Join(out, " ")
	}

	return s
}

// ─────────────────────────────────────────────────────────────────
// legacyEnrichExecutor — old "enrich" step
//
// Original semantics: enrich findings with CVE data from NVD/OSV.
// We don't have an enrichment service here in the foundation layer,
// so we record the request and let the engine/handler delegate to
// existing internal/threatintel package.
//
// For now: returns the requested sources/fields as output, allowing
// downstream steps (or human review) to act on it.
// ─────────────────────────────────────────────────────────────────

type legacyEnrichExecutor struct{}

func (e *legacyEnrichExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg := parseLegacyConfig(n.ConfigRaw)
	out := map[string]interface{}{
		"_legacy_step": "enrich",
		"source":       cfg["source"],
		"fields":       cfg["fields"],
		"note":         "enrichment delegated to threat_intel package; output is the request descriptor",
	}
	data, err := json.Marshal(out)
	return data, "", err
}

// ─────────────────────────────────────────────────────────────────
// legacyBlockExecutor — old "block" step (block CI pipeline)
//
// Original: post a status check to GitHub/GitLab marking pipeline as failed.
// Without HTTP wiring here, we describe the action; engine/handler can
// translate to actual HTTP step at runtime.
// ─────────────────────────────────────────────────────────────────

type legacyBlockExecutor struct{}

func (e *legacyBlockExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg := parseLegacyConfig(n.ConfigRaw)
	out := map[string]interface{}{
		"_legacy_step": "block",
		"provider":     cfg["provider"],
		"status":       defaultStr(cfg["status"], "failure"),
		"context":      cfg["context"],
		"action":       "blocked CI pipeline (request descriptor — handler translates to HTTP)",
	}
	data, err := json.Marshal(out)
	return data, "", err
}

// ─────────────────────────────────────────────────────────────────
// legacyRemediateExecutor — old "remediate" step
//
// Original: assign findings to user, set priority. Translates to a write
// against the remediations table (Phase 1 work). We emit a descriptor
// here; engine/handler binds it to store.UpdateRemediationFields.
// ─────────────────────────────────────────────────────────────────

type legacyRemediateExecutor struct{}

func (e *legacyRemediateExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg := parseLegacyConfig(n.ConfigRaw)
	out := map[string]interface{}{
		"_legacy_step": "remediate",
		"assignee":     cfg["assignee"],
		"priority":     cfg["priority"],
		"status":       defaultStr(cfg["status"], "in_progress"),
		"action":       "remediation update descriptor — handler binds to store.UpdateRemediationFields",
	}
	data, err := json.Marshal(out)
	return data, "", err
}

func defaultStr(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
}
