// Standalone Trivy API server for VSP PRO CWPP module.
//
// Why standalone? The main vsp-gateway has complex lifecycle issues
// (auth middleware, SSE worker panic, systemd cgroup kill). For P0 we
// run Trivy as a separate microservice on port 8090, fully isolated.
//
// Build: go build -o vsp-trivy-api ./cmd/trivy-api
// Run:   ./vsp-trivy-api
// Test:  curl http://127.0.0.1:8090/api/v1/container/seed -X POST
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	listenAddr  = ":8090"
	scanTimeout = 5 * time.Minute
	trivyBin    = "trivy"
)

// ─── Types ────────────────────────────────────────────────────────────

type Image struct {
	ID         string    `json:"id"`
	Ref        string    `json:"ref"`
	Digest     string    `json:"digest,omitempty"`
	OS         string    `json:"os,omitempty"`
	OSVersion  string    `json:"os_version,omitempty"`
	SizeMB     int       `json:"size_mb"`
	Layers     int       `json:"layers"`
	Critical   int       `json:"crit"`
	High       int       `json:"high"`
	Medium     int       `json:"med"`
	Low        int       `json:"low"`
	TotalCVE   int       `json:"total_cve"`
	Signed     bool      `json:"signed"`
	SBOMAttest bool      `json:"sbom_attested"`
	ScannedAt  time.Time `json:"scanned_at"`
	Status     string    `json:"status"`
}

type Vulnerability struct {
	CVE       string `json:"cve"`
	Severity  string `json:"severity"`
	Library   string `json:"library"`
	Installed string `json:"installed_version"`
	FixedIn   string `json:"fixed_version,omitempty"`
	Title     string `json:"title,omitempty"`
	URL       string `json:"url,omitempty"`
}

type ScanResult struct {
	Image           Image           `json:"image"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Error           string          `json:"error,omitempty"`
}

type trivyOutput struct {
	Metadata struct {
		OS struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
		ImageConfig struct {
			Size   int64 `json:"size"`
			RootFS struct {
				DiffIDs []string `json:"diff_ids"`
			} `json:"rootfs"`
		} `json:"ImageConfig"`
		RepoDigests []string `json:"RepoDigests"`
	} `json:"Metadata"`
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion,omitempty"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title,omitempty"`
			PrimaryURL       string `json:"PrimaryURL,omitempty"`
		} `json:"Vulnerabilities,omitempty"`
	} `json:"Results"`
}

// ─── Storage (in-memory) ─────────────────────────────────────────────

var (
	mu        sync.RWMutex
	scanMutex sync.Mutex // serialize Trivy invocations (DB lock)
	results   = map[string]*ScanResult{}
)

func imageID(ref string) string {
	h := sha256.Sum256([]byte(ref))
	return "img_" + hex.EncodeToString(h[:8])
}

// ─── Scanner ──────────────────────────────────────────────────────────

func scan(ctx context.Context, ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return errors.New("ref required")
	}
	id := imageID(ref)

	// Mark scanning
	mu.Lock()
	results[id] = &ScanResult{
		Image: Image{ID: id, Ref: ref, Status: "scanning", ScannedAt: time.Now()},
	}
	mu.Unlock()

	// Serialize Trivy invocations — Trivy uses a shared cache DB with a lock file,
	// so parallel runs cause "another process is using the DB" errors.
	scanMutex.Lock()
	defer scanMutex.Unlock()

	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, trivyBin,
		"image",
		"--format", "json",
		"--quiet",
		"--scanners", "vuln",
		"--skip-version-check",
		ref,
	)
	out, err := cmd.Output()
	if err != nil {
		mu.Lock()
		results[id].Image.Status = "failed"
		results[id].Error = fmt.Sprintf("trivy: %v", err)
		mu.Unlock()
		return err
	}

	var raw trivyOutput
	if err := json.Unmarshal(out, &raw); err != nil {
		mu.Lock()
		results[id].Image.Status = "failed"
		results[id].Error = fmt.Sprintf("parse: %v", err)
		mu.Unlock()
		return err
	}

	r := &ScanResult{
		Image: Image{
			ID:        id,
			Ref:       ref,
			OS:        raw.Metadata.OS.Family,
			OSVersion: raw.Metadata.OS.Name,
			SizeMB:    int(raw.Metadata.ImageConfig.Size / (1024 * 1024)),
			Layers:    len(raw.Metadata.ImageConfig.RootFS.DiffIDs),
			ScannedAt: time.Now(),
			Status:    "ok",
		},
		Vulnerabilities: []Vulnerability{},
	}
	if len(raw.Metadata.RepoDigests) > 0 {
		r.Image.Digest = raw.Metadata.RepoDigests[0]
	}

	for _, t := range raw.Results {
		for _, v := range t.Vulnerabilities {
			r.Vulnerabilities = append(r.Vulnerabilities, Vulnerability{
				CVE:       v.VulnerabilityID,
				Severity:  v.Severity,
				Library:   v.PkgName,
				Installed: v.InstalledVersion,
				FixedIn:   v.FixedVersion,
				Title:     v.Title,
				URL:       v.PrimaryURL,
			})
			switch v.Severity {
			case "CRITICAL":
				r.Image.Critical++
			case "HIGH":
				r.Image.High++
			case "MEDIUM":
				r.Image.Medium++
			case "LOW":
				r.Image.Low++
			}
		}
	}
	r.Image.TotalCVE = len(r.Vulnerabilities)

	mu.Lock()
	results[id] = r
	mu.Unlock()
	log.Printf("scan complete: %s → %d CVE (C:%d H:%d M:%d L:%d)",
		ref, r.Image.TotalCVE, r.Image.Critical, r.Image.High, r.Image.Medium, r.Image.Low)
	return nil
}

func scanAsync(ref string) string {
	id := imageID(ref)
	go func() {
		_ = scan(context.Background(), ref)
	}()
	return id
}

// ─── HTTP handlers ────────────────────────────────────────────────────

func corsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	corsHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func handleListImages(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		corsHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	mu.RLock()
	imgs := make([]Image, 0, len(results))
	for _, res := range results {
		imgs = append(imgs, res.Image)
	}
	mu.RUnlock()
	// sort by ScannedAt desc
	for i := 1; i < len(imgs); i++ {
		for j := i; j > 0 && imgs[j].ScannedAt.After(imgs[j-1].ScannedAt); j-- {
			imgs[j], imgs[j-1] = imgs[j-1], imgs[j]
		}
	}
	writeJSON(w, 200, imgs)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		corsHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var req struct {
		Ref string `json:"ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Ref == "" {
		writeJSON(w, 400, map[string]string{"error": "ref required"})
		return
	}
	id := scanAsync(req.Ref)
	writeJSON(w, 202, map[string]string{"id": id, "status": "scanning", "ref": req.Ref})
}

func handleGetScan(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		corsHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/container/scan/")
	mu.RLock()
	res, ok := results[id]
	mu.RUnlock()
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "not found: " + id})
		return
	}
	writeJSON(w, 200, res)
}

func handleSeed(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		corsHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	images := []string{
		"redis:7-alpine",
		"nginx:1.25-alpine",
		"alpine:3.19",
		"busybox:1.36",
	}
	ids := make([]string, 0, len(images))
	for _, ref := range images {
		ids = append(ids, scanAsync(ref))
	}
	writeJSON(w, 202, map[string]any{
		"queued": ids,
		"images": images,
		"note":   "Scans running in background. Poll GET /api/v1/container/images.",
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "ok — vsp-trivy-api on %s\n", listenAddr)
}

// ─── Main ─────────────────────────────────────────────────────────────

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHealth)
	mux.HandleFunc("/api/v1/container/images", handleListImages)
	mux.HandleFunc("/api/v1/container/scan", handleScan)
	mux.HandleFunc("/api/v1/container/scan/", handleGetScan) // trailing slash for {id}
	mux.HandleFunc("/api/v1/container/seed", handleSeed)

	log.Printf("VSP Trivy API listening on %s", listenAddr)
	log.Printf("Try: curl -X POST http://127.0.0.1%s/api/v1/container/seed", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}
