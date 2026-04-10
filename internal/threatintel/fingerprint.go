package threatintel

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/vsp/platform/internal/store"
)

// Fingerprint tạo unique hash cho 1 finding
// dựa trên tool + rule_id + path + line (không phụ thuộc run_id)
func Fingerprint(f store.Finding) string {
	// Normalize path — bỏ absolute prefix, chỉ giữ relative
	path := normalizePath(f.Path)
	key := fmt.Sprintf("%s|%s|%s|%d", f.Tool, f.RuleID, path, f.LineNum)
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", h[:8]) // 16 char hex
}

// FingerprintGroup nhóm findings theo fingerprint
// trả về: map[fingerprint][]Finding
func FingerprintGroup(findings []store.Finding) map[string][]store.Finding {
	groups := make(map[string][]store.Finding)
	for _, f := range findings {
		fp := Fingerprint(f)
		groups[fp] = append(groups[fp], f)
	}
	return groups
}

// Deduplicate trả về 1 finding đại diện cho mỗi unique fingerprint
// ưu tiên finding mới nhất, giữ metadata về số lần xuất hiện
type DeduplicatedFinding struct {
	store.Finding
	Fingerprint     string `json:"fingerprint"`
	OccurrenceCount int    `json:"occurrence_count"`
	FirstSeen       string `json:"first_seen"`
	LastSeen        string `json:"last_seen"`
	AcrossRuns      int    `json:"across_runs"`
	IsPersistent    bool   `json:"is_persistent"` // true nếu xuất hiện >= 3 runs
	IsRegression    bool   `json:"is_regression"` // true nếu biến mất rồi xuất hiện lại
}

func Deduplicate(findings []store.Finding) []DeduplicatedFinding {
	groups := FingerprintGroup(findings)
	result := make([]DeduplicatedFinding, 0, len(groups))

	for fp, group := range groups {
		// Lấy finding mới nhất làm representative
		best := group[0]
		firstSeen := group[0].CreatedAt
		lastSeen := group[0].CreatedAt
		runIDs := make(map[string]bool)

		for _, f := range group {
			if f.CreatedAt.After(best.CreatedAt) {
				best = f
			}
			if f.CreatedAt.Before(firstSeen) {
				firstSeen = f.CreatedAt
			}
			if f.CreatedAt.After(lastSeen) {
				lastSeen = f.CreatedAt
			}
			runIDs[f.RunID] = true
		}

		// IsRegression: tìm gap trong timeline (biến mất rồi xuất hiện lại)
		isRegression := false
		if len(runIDs) >= 2 && len(group) >= 2 {
			// Sort by time — gap > 7 days giữa consecutive sightings = regression
			gap := lastSeen.Sub(firstSeen)
			if gap.Hours() > 168 && len(runIDs) < len(group) {
				isRegression = true
			}
		}
		df := DeduplicatedFinding{
			Finding:         best,
			Fingerprint:     fp,
			OccurrenceCount: len(group),
			FirstSeen:       firstSeen.Format("2006-01-02T15:04:05Z"),
			LastSeen:        lastSeen.Format("2006-01-02T15:04:05Z"),
			AcrossRuns:      len(runIDs),
			IsPersistent:    len(runIDs) >= 3,
			IsRegression:    isRegression,
		}
		result = append(result, df)
	}

	return result
}

func normalizePath(path string) string {
	// Remove absolute prefixes
	// Strip absolute prefixes to prevent path disclosure in fingerprints
	for _, prefix := range []string{
		"/home/", "/tmp/", "/opt/", "/var/", "/root/", "/usr/",
		"../../../../", "../../../", "../../", "../",
	} {
		if idx := strings.Index(path, prefix); idx >= 0 {
			after := path[idx+len(prefix):]
			parts := strings.SplitN(after, "/", 3)
			if len(parts) >= 2 {
				path = strings.Join(parts[1:], "/")
			} else if len(parts) == 1 {
				path = parts[0]
			}
			break
		}
	}
	// Remove Windows-style absolute paths
	if len(path) > 2 && path[1] == ':' {
		path = path[2:]
	}
	return strings.ToLower(strings.TrimSpace(path))
}
