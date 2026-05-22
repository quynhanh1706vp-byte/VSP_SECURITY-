package handler

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoErrLeakInClientResponse ratchets the "jsonError + err.Error()"
// information-disclosure pattern.
//
// Why this matters: pgx error strings include the SQL text and
// table/column names ("ERROR: column "blah" of relation "users" does
// not exist"). os errors include filesystem paths. net errors include
// internal hostnames. Wrapping them into a JSON response means any
// unauthenticated client can fingerprint the schema and infra layout.
//
// 8 sites were converted to jsonInternalError on 2026-05-12; the rest
// (~112 at audit time) are TODO. This test ratchets NEW additions —
// existing sites are allowed via in-line comment annotation.
//
// New handler code:
//
//	BAD:  jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
//	GOOD: jsonInternalError(w, r, "db error", err)
//
// Existing site too risky to refactor right now? Annotate:
//
//	jsonError(w, "x: "+err.Error(), 500) // safe-err-leak: <rationale>
func TestNoErrLeakInClientResponse(t *testing.T) {
	// `jsonError(w, "...: "+err.Error(), ...)` or `http.Error(...err.Error())`
	leakRe := regexp.MustCompile(`(jsonError|http\.Error)\([^)]*err\.Error\(\)`)
	allowRe := regexp.MustCompile(`safe-err-leak`)

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
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		lines := []string{}
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		for i, line := range lines {
			if !leakRe.MatchString(line) {
				continue
			}
			lo, hi := i-2, i+2
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

	// Ratchet history:
	//   2026-05-12 morning: 110 sites at first audit
	//   2026-05-12 noon  :  20 sites after batch jsonInternalError convert
	//   2026-05-12 PM    :  12 sites after annotating intentional 4xx
	//                       validation feedback (safe-err-leak)
	//
	// Remaining 12 are all client-facing 4xx validation messages where
	// err.Error() text IS the user feedback (e.g. URL parse failures
	// in /vsp/run trigger). Each PR is expected to hold the line; new
	// leak sites bump the count and trip the gate. The reduction
	// trajectory was -98 in one day so the floor here is intentionally
	// tight.
	const ratchet = 12
	if len(bad) > ratchet {
		t.Errorf("err.Error() leak count %d > ratchet %d", len(bad), ratchet)
		t.Errorf("New code must use jsonInternalError(w, r, msg, err)")
		t.Errorf("or annotate the line with // safe-err-leak: <rationale>")
		t.Errorf("First 20 over-budget sites:")
		for i, h := range bad {
			if i >= 20 {
				t.Errorf("  ... %d more", len(bad)-20)
				break
			}
			t.Errorf("  %s:%d  %s", h.file, h.line, h.text)
		}
	}
}
