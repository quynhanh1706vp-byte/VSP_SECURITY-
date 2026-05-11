// cmd/scheduler-api/cron.go
//
// Pure-Go cron expression parser. No external deps.
// Supports the standard 5-field format (minute hour dom month dow) with:
//   - Specific values:    0,15,30,45
//   - Ranges:             1-5
//   - Steps:              */15, 0-30/5
//   - Lists:              0,15,30
//   - Wildcards:          *
//   - Day names:          Sun,Mon,...,Sat (case-insensitive)
//   - Month names:        Jan,Feb,...,Dec (case-insensitive)
package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CronExpr holds a parsed expression as bitmasks for fast match.
type CronExpr struct {
	Raw     string
	Minute  uint64 // 0-59  → bit i = minute i allowed
	Hour    uint64 // 0-23
	DOM     uint64 // 1-31
	Month   uint64 // 1-12
	DOW     uint64 // 0-6 (Sun=0)
	domStar bool   // true if DOM was '*'
	dowStar bool   // true if DOW was '*'
}

// Parse parses a 5-field cron expression.
func Parse(expr string) (*CronExpr, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, errors.New("empty cron expression")
	}
	// Handle a few well-known shortcuts
	switch strings.ToLower(expr) {
	case "@yearly", "@annually":
		expr = "0 0 1 1 *"
	case "@monthly":
		expr = "0 0 1 * *"
	case "@weekly":
		expr = "0 0 * * 0"
	case "@daily", "@midnight":
		expr = "0 0 * * *"
	case "@hourly":
		expr = "0 * * * *"
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("need 5 fields (minute hour dom month dow), got %d", len(fields))
	}
	c := &CronExpr{Raw: expr}
	var err error
	if c.Minute, err = parseField(fields[0], 0, 59, nil); err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	if c.Hour, err = parseField(fields[1], 0, 23, nil); err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	if c.DOM, err = parseField(fields[2], 1, 31, nil); err != nil {
		return nil, fmt.Errorf("dom: %w", err)
	}
	c.domStar = fields[2] == "*"
	if c.Month, err = parseField(fields[3], 1, 12, monthNames); err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	if c.DOW, err = parseField(fields[4], 0, 6, dowNames); err != nil {
		return nil, fmt.Errorf("dow: %w", err)
	}
	c.dowStar = fields[4] == "*"
	return c, nil
}

var (
	monthNames = map[string]int{
		"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
		"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
	}
	dowNames = map[string]int{
		"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
		"sunday": 0, "monday": 1, "tuesday": 2, "wednesday": 3,
		"thursday": 4, "friday": 5, "saturday": 6,
	}
)

func parseField(field string, lo, hi int, names map[string]int) (uint64, error) {
	var mask uint64
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		step := 1
		if i := strings.Index(part, "/"); i >= 0 {
			s, err := strconv.Atoi(part[i+1:])
			if err != nil || s < 1 {
				return 0, fmt.Errorf("invalid step %q", part)
			}
			step = s
			part = part[:i]
		}
		var start, end int
		if part == "*" {
			start, end = lo, hi
		} else if i := strings.Index(part, "-"); i >= 0 {
			a, errA := lookupOrInt(part[:i], names)
			b, errB := lookupOrInt(part[i+1:], names)
			if errA != nil || errB != nil {
				return 0, fmt.Errorf("invalid range %q", part)
			}
			start, end = a, b
		} else {
			n, err := lookupOrInt(part, names)
			if err != nil {
				return 0, fmt.Errorf("invalid value %q", part)
			}
			start, end = n, n
		}
		if start < lo || end > hi || start > end {
			return 0, fmt.Errorf("out of range %d-%d (allowed %d-%d)", start, end, lo, hi)
		}
		for v := start; v <= end; v += step {
			mask |= 1 << uint(v) //#nosec G115 -- v bounded to [lo,hi] above (max 59)
		}
	}
	if mask == 0 {
		return 0, errors.New("empty mask")
	}
	return mask, nil
}

func lookupOrInt(s string, names map[string]int) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if names != nil {
		if v, ok := names[s]; ok {
			return v, nil
		}
	}
	return strconv.Atoi(s)
}

// Match returns true if t matches the expression.
func (c *CronExpr) Match(t time.Time) bool {
	if c.Minute&(1<<uint(t.Minute())) == 0 { //#nosec G115 -- Minute() bounded to [0,59]
		return false
	}
	if c.Hour&(1<<uint(t.Hour())) == 0 { //#nosec G115 -- Hour() bounded to [0,23]
		return false
	}
	if c.Month&(1<<uint(t.Month())) == 0 { //#nosec G115 -- Month() bounded to [1,12]
		return false
	}
	domOK := c.DOM&(1<<uint(t.Day())) != 0      //#nosec G115 -- Day() bounded to [1,31]
	dowOK := c.DOW&(1<<uint(t.Weekday())) != 0 //#nosec G115 -- Weekday() bounded to [0,6]
	// Standard cron: if both DOM and DOW are restricted (not '*'),
	// the job matches if EITHER one matches (OR). If one is '*', AND.
	if c.domStar && c.dowStar {
		return true
	}
	if c.domStar {
		return dowOK
	}
	if c.dowStar {
		return domOK
	}
	return domOK || dowOK
}

// Next computes the next time at or after `from` that matches.
// Returns time.Time{} if no match within ~5 years (safety cap).
func (c *CronExpr) Next(from time.Time) time.Time {
	t := from.Truncate(time.Minute).Add(time.Minute)
	limit := from.Add(5 * 365 * 24 * time.Hour)
	for t.Before(limit) {
		if c.Match(t) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}
}

// NextN returns the next N fire times from `from`.
func (c *CronExpr) NextN(from time.Time, n int) []time.Time {
	out := make([]time.Time, 0, n)
	cur := from
	for len(out) < n {
		nxt := c.Next(cur)
		if nxt.IsZero() {
			break
		}
		out = append(out, nxt)
		cur = nxt
	}
	return out
}

// Describe returns a short human-readable description.
// Heuristics — covers ~80% of real-world expressions, falls back to raw.
func (c *CronExpr) Describe() string {
	parts := strings.Fields(c.Raw)
	if len(parts) != 5 {
		return c.Raw
	}
	min, hr, dom, mon, dow := parts[0], parts[1], parts[2], parts[3], parts[4]

	// Time piece
	timePiece := ""
	if isSpecificTime(min, hr) {
		timePiece = fmt.Sprintf("at %02s:%02s", hr, min)
	} else if hr == "*" && strings.HasPrefix(min, "*/") {
		timePiece = "every " + strings.TrimPrefix(min, "*/") + " minutes"
	} else if min == "0" && strings.HasPrefix(hr, "*/") {
		timePiece = "every " + strings.TrimPrefix(hr, "*/") + " hours"
	} else if min == "0" && hr == "*" {
		timePiece = "every hour"
	} else if min == "*" && hr == "*" {
		timePiece = "every minute"
	} else {
		timePiece = fmt.Sprintf("at %s:%s", hr, min)
	}

	// Date piece
	datePiece := ""
	switch {
	case dom == "*" && mon == "*" && dow == "*":
		datePiece = "every day"
	case dom == "*" && mon == "*" && dow != "*":
		datePiece = "on " + describeDOW(dow)
	case dow == "*" && mon == "*" && dom != "*":
		datePiece = "on day " + dom + " of every month"
	case dow == "*" && dom == "*":
		datePiece = "in " + describeMonth(mon)
	case dom != "*" && mon != "*":
		datePiece = "on " + dom + " " + describeMonth(mon)
	default:
		datePiece = ""
	}

	out := timePiece
	if datePiece != "" {
		out += ", " + datePiece
	}
	return cap1(out)
}

func isSpecificTime(min, hr string) bool {
	_, e1 := strconv.Atoi(min)
	_, e2 := strconv.Atoi(hr)
	return e1 == nil && e2 == nil
}

func describeDOW(s string) string {
	names := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 6 {
		return names[n]
	}
	if strings.Contains(s, "-") {
		return s + " (range)"
	}
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if n, err := strconv.Atoi(p); err == nil && n >= 0 && n <= 6 {
				out = append(out, names[n])
			} else {
				out = append(out, p)
			}
		}
		return strings.Join(out, "/")
	}
	return s
}

func describeMonth(s string) string {
	names := []string{"", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= 12 {
		return names[n]
	}
	return s
}

func cap1(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
