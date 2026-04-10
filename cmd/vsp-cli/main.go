package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const VERSION = "1.0.0"
const DEFAULT_HOST = "http://127.0.0.1:8921"

var host = DEFAULT_HOST

func main() {
	if h := os.Getenv("VSP_HOST"); h != "" {
		host = h
	}
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "p4":
		if len(args) == 0 {
			p4Status()
			return
		}
		switch args[0] {
		case "status":
			p4Status()
		case "score":
			p4Score()
		case "poam":
			p4POAM()
		case "sync":
			p4Sync()
		case "report":
			p4Report(args[1:])
		case "oscal":
			p4OSCAL()
		case "pipeline":
			p4Pipeline()
		default:
			fmt.Printf("Unknown p4 command: %s\n", args[0])
		}
	case "health":
		health()
	case "version":
		fmt.Printf("vsp version %s\n", VERSION)
	case "help":
		printHelp()
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printHelp()
	}
}

func apiKey() string {
	if k := os.Getenv("VSP_API_KEY"); k != "" {
		return k
	}
	// No hardcoded fallback — require explicit API key
	fmt.Fprintln(os.Stderr, "WARNING: VSP_API_KEY not set — requests may be unauthorized")
	fmt.Fprintln(os.Stderr, "  Set: export VSP_API_KEY=<your-api-key>")
	return ""
}

func get(path string) (map[string]interface{}, error) {
	//nolint:gosec // G704: host from VSP_HOST env var, controlled by operator
	req, err := http.NewRequest("GET", host+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", apiKey())
	req.Header.Set("Referer", host+"/p4")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)
	return result, nil
}

func post(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("POST", host+path, strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey())
	req.Header.Set("Referer", host+"/p4")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)
	return result, nil
}

func health() {
	fmt.Print("Checking VSP health... ")
	d, err := get("/api/p4/health/detailed")
	if err != nil {
		fmt.Println("❌ Cannot connect to", host)
		return
	}
	fmt.Println("✅")
	fmt.Printf("  Status:   %s\n", d["status"])
	fmt.Printf("  Version:  %s\n", d["version"])
	fmt.Printf("  Uptime:   %s\n", d["uptime"])
	if p4, ok := d["p4"].(map[string]interface{}); ok {
		fmt.Printf("  P4:       %v%% (%v)\n", p4["readiness"], p4["ato_status"])
	}
	if sys, ok := d["system"].(map[string]interface{}); ok {
		fmt.Printf("  Memory:   %vMB\n", sys["mem_alloc_mb"])
	}
}

func p4Status() {
	fmt.Println("━━━ VSP P4 Compliance Status ━━━━━━━━━━━━━━━━━━━━━━━━━━")
	d, err := get("/api/p4/zt/status")
	if err != nil {
		fmt.Println("❌ Error:", err)
		return
	}

	var readiness float64
	switch v := d["p4_readiness"].(type) {
	case float64:
		readiness = v
	case int:
		readiness = float64(v)
	}
	achieved := d["p4_achieved"]
	fmt.Printf("  P4 Readiness: %.0f%%", readiness)
	if achieved == true {
		fmt.Println(" ✅ ACHIEVED")
	} else {
		fmt.Println(" ⚠️  IN PROGRESS")
	}
	fmt.Printf("  Overall ZT:   %v%%\n", d["overall_score"])

	if pillars, ok := d["pillars"].(map[string]interface{}); ok {
		fmt.Println("\n  Zero Trust Pillars:")
		for _, p := range pillars {
			if pmap, ok := p.(map[string]interface{}); ok {
				var score float64
				switch v := pmap["score"].(type) {
				case float64:
					score = v
				case int:
					score = float64(v)
				}
				name := fmt.Sprintf("%v", pmap["name"])
				bar := strings.Repeat("█", int(score/10)) + strings.Repeat("░", 10-int(score/10))
				fmt.Printf("    %-30s %s %.0f%%\n", name, bar, score)
			}
		}
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func p4Score() {
	d, err := get("/api/p4/rmf")
	if err != nil {
		fmt.Println("❌ Error:", err)
		return
	}
	fmt.Println("━━━ VSP Compliance Scores ━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  ATO Status:      %v\n", d["ato_status"])
	fmt.Printf("  ConMon Score:    %v/100\n", d["conmon_score"])
	if pipe, err := get("/api/p4/pipeline/latest"); err == nil {
		if s, ok := pipe["summary"].(map[string]interface{}); ok {
			fmt.Printf("  Pipeline Score:  %v%%\n", s["score"])
			if fw, ok := s["frameworks"].(map[string]interface{}); ok {
				for name, f := range fw {
					if fm, ok := f.(map[string]interface{}); ok {
						fmt.Printf("  %-16s %v%%\n", name+":", fm["percent"])
					}
				}
			}
		}
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func p4POAM() {
	d, err := get("/api/p4/rmf")
	if err != nil {
		fmt.Println("❌ Error:", err)
		return
	}
	items, _ := d["poam_items"].([]interface{})
	open := 0
	fmt.Println("━━━ Open POA&M Items ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	for _, item := range items {
		if m, ok := item.(map[string]interface{}); ok {
			status := fmt.Sprintf("%v", m["status"])
			if status == "open" || status == "in_remediation" {
				open++
				sev := fmt.Sprintf("%v", m["severity"])
				icon := "🔵"
				if sev == "CRITICAL" {
					icon = "🔴"
				} else if sev == "HIGH" {
					icon = "🟠"
				}
				fmt.Printf("  %s [%s] %s — %v\n", icon, sev, m["id"], m["weakness_name"])
				fmt.Printf("     Control: %v | Due: %v\n", m["control_id"], m["scheduled_completion"])
			}
		}
	}
	fmt.Printf("\n  Total open: %d\n", open)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func p4Sync() {
	fmt.Print("Syncing VSP findings → POA&M... ")
	d, err := post("/api/p4/findings/sync")
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	if sync, ok := d["sync"].(map[string]interface{}); ok {
		fmt.Printf("✅ Created: %v, Updated: %v, Skipped: %v\n",
			sync["created"], sync["updated"], sync["skipped"])
	} else {
		fmt.Println("✅ Done")
	}
}

func p4Pipeline() {
	d, err := get("/api/p4/pipeline/latest")
	if err != nil {
		fmt.Println("❌ Error:", err)
		return
	}
	fmt.Println("━━━ Latest Pipeline Run ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Run ID:  %v\n", d["id"])
	fmt.Printf("  Status:  %v\n", d["status"])
	if s, ok := d["summary"].(map[string]interface{}); ok {
		fmt.Printf("  Score:   %v%%\n", s["score"])
		fmt.Printf("  Pass:    %v\n", s["pass"])
		fmt.Printf("  Warn:    %v\n", s["warn"])
		fmt.Printf("  Fail:    %v\n", s["fail"])
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func p4Report(args []string) {
	period := "monthly"
	if len(args) > 0 {
		period = args[0]
	}
	fmt.Printf("Generating %s ConMon report... ", period)
	d, err := get("/api/p4/conmon/report?period=" + period)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	fmt.Println("✅")

	if ex, ok := d["executive_summary"].(map[string]interface{}); ok {
		fmt.Println("\n━━━ Executive Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Printf("  P4 Readiness:  %v%%\n", ex["p4_readiness"])
		fmt.Printf("  ConMon Score:  %v/100\n", ex["conmon_score"])
		fmt.Printf("  Risk Posture:  %v\n", ex["risk_posture"])
		fmt.Printf("  ATO Status:    %v\n", ex["ato_status"])
	}
	if actions, ok := d["next_actions"].([]interface{}); ok {
		fmt.Println("\n  Next Actions:")
		for _, a := range actions {
			fmt.Printf("    → %v\n", a)
		}
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Save to file
	fname := fmt.Sprintf("vsp-conmon-%s-%s.json", period, time.Now().Format("2006-01-02"))
	b, _ := json.MarshalIndent(d, "", "  ")
	os.WriteFile(fname, b, 0644) //#nosec G703 G703 -- CLI tool, fname from timestamp
	fmt.Printf("\n  Saved to: %s\n", fname)
}

func p4OSCAL() {
	fmt.Print("Exporting OSCAL SSP... ")
	d, err := get("/api/p4/oscal/ssp")
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	fname := fmt.Sprintf("vsp-ssp-oscal-%s.json", time.Now().Format("2006-01-02"))
	b, _ := json.MarshalIndent(d, "", "  ")
	os.WriteFile(fname, b, 0644)
	fmt.Printf("✅ Saved to: %s\n", fname)
	if ssp, ok := d["system-security-plan"].(map[string]interface{}); ok {
		if meta, ok := ssp["metadata"].(map[string]interface{}); ok {
			fmt.Printf("  OSCAL version: %v\n", meta["oscal-version"])
			fmt.Printf("  SSP version:   %v\n", meta["version"])
		}
		if ci, ok := ssp["control-implementation"].(map[string]interface{}); ok {
			if reqs, ok := ci["implemented-requirements"].([]interface{}); ok {
				fmt.Printf("  Controls:      %d implemented\n", len(reqs))
			}
		}
	}
}

func printHelp() {
	fmt.Printf(`VSP CLI v%s — DoD Zero Trust P4 Compliance Tool

USAGE:
  vsp <command> [subcommand] [options]

COMMANDS:
  health              Check VSP service health
  p4 status           Show Zero Trust 7-pillar scorecard
  p4 score            Show all framework compliance scores
  p4 poam             List open POA&M items
  p4 sync             Sync VSP findings → POA&M
  p4 pipeline         Show latest compliance pipeline run
  p4 report [period]  Generate ConMon report (weekly|monthly)
  p4 oscal            Export NIST OSCAL 1.1.2 SSP JSON
  version             Show CLI version
  help                Show this help

ENVIRONMENT:
  VSP_HOST            Gateway URL (default: http://127.0.0.1:8921)
  VSP_API_KEY         API key for authentication (required for authenticated endpoints)

EXAMPLES:
  vsp health
  vsp p4 status
  vsp p4 sync
  vsp p4 report monthly
  vsp p4 oscal
  VSP_HOST=https://api.yourdomain.com vsp p4 status

`, VERSION)
}
