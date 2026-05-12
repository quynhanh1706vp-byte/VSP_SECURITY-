package handler

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoFalseTotalCount pins the "total: len(rows)" anti-pattern across
// every handler in this package. The bug class: a handler accepts a
// `?limit=N` query param, runs a LIMIT-N SELECT, then returns
// `{"total": len(rows)}` to the client. The FE shows that "total" as
// a KPI and the user sees a different number on every tab depending
// on which fetch ran with which limit.
//
// User's 2026-05-12 bug report: "lúc total runs = 200 lúc total = 50"
// — exact symptom. Fixed in runs.go via store.CountRuns + true
// total returned.
//
// This test prevents recurrence: any handler file that contains BOTH
// (a) a `queryInt(r, "limit", ...)` call AND
// (b) a `"total": len(` literal
// fails the test unless the function has a `// page-size-not-total`
// allowlist comment within 3 lines of the literal.
//
// The allowlist exists because some handlers genuinely return non-
// paginated data and "total = len(items)" is correct. Those callers
// can opt out explicitly:
//
//	jsonOK(w, map[string]any{
//	  "items": out,
//	  "total": len(out), // page-size-not-total: returns all rows
//	})
func TestNoFalseTotalCount(t *testing.T) {
	totalLenRe := regexp.MustCompile(`"(total|count)":\s*len\(`)
	limitRe := regexp.MustCompile(`queryInt\(r,\s*"limit"|r\.URL\.Query\(\)\.Get\("limit"\)|Limit\s+int\s+\x60json:"limit"\x60`)
	// `page-size-not-total:` and `safe-len:` are both explicit opt-outs.
	// `page-size-not-total` was the original ratchet token; `safe-len:` was
	// adopted in the 2026-05-12 audit to distinguish "deliberately
	// non-paginated" sites (in-memory list, hardcoded set, unlimited query)
	// from the still-pending wire-CountX TODOs.
	allowRe := regexp.MustCompile(`page-size-not-total|safe-len:`)

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	type hit struct {
		file string
		line int
		text string
	}
	var bad []hit

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		// Whole-file check: does it accept a limit param at all?
		if !limitRe.Match(data) {
			continue
		}
		// Per-line check for the anti-pattern.
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		lines := []string{}
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		for i, line := range lines {
			if !totalLenRe.MatchString(line) {
				continue
			}
			// Look at ±3 lines for the allowlist comment.
			lo, hi := i-3, i+3
			if lo < 0 {
				lo = 0
			}
			if hi >= len(lines) {
				hi = len(lines) - 1
			}
			block := strings.Join(lines[lo:hi+1], "\n")
			if allowRe.MatchString(block) {
				continue
			}
			bad = append(bad, hit{f, i + 1, strings.TrimSpace(line)})
		}
	}

	if len(bad) == 0 {
		return
	}
	t.Errorf("found %d handler(s) returning false total/count (page size masquerading as full row count):", len(bad))
	for _, h := range bad {
		t.Errorf("  %s:%d  %s", h.file, h.line, h.text)
	}
	t.Errorf("")
	t.Errorf("Fix one of:")
	t.Errorf("  (a) Add a Count* store helper, return that as total")
	t.Errorf("      (see store.CountRuns + handler/runs.go for the pattern)")
	t.Errorf("  (b) Rename 'total' -> 'count' or 'page_size' to be honest")
	t.Errorf("  (c) If returning all rows (no pagination effect): annotate")
	t.Errorf("      with // page-size-not-total: <rationale>")
}
