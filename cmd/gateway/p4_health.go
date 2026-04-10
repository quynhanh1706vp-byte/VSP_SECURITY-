package main

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime"
	"time"
)

type HealthStatus struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Uptime    string            `json:"uptime"`
	P4        P4HealthDetail    `json:"p4"`
	Services  map[string]string `json:"services"`
	System    SystemInfo        `json:"system"`
	Timestamp time.Time         `json:"timestamp"`
}

type P4HealthDetail struct {
	Readiness  int    `json:"readiness"`
	Achieved   bool   `json:"achieved"`
	ATOStatus  string `json:"ato_status"`
	ConMon     int    `json:"conmon_score"`
	LastUpdate time.Time `json:"last_update"`
}

type SystemInfo struct {
	Goroutines int    `json:"goroutines"`
	MemAllocMB uint64 `json:"mem_alloc_mb"`
	GOOS       string `json:"goos"`
	GoVersion  string `json:"go_version"`
}

var p4StartTime = time.Now()

func handleP4HealthDetailed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Vary", "Origin")

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	ztState.mu.RLock()
	p4r := ztState.P4Readiness
	p4a := ztState.P4Achieved
	lastUp := ztState.LastUpdated
	ztState.mu.RUnlock()

	rmfStore.mu.RLock()
	pkg := rmfStore.packages["VSP-DOD-2025-001"]
	atoStatus := "unknown"
	conmon := 0
	if pkg != nil { atoStatus = pkg.ATOStatus; conmon = pkg.ConMonScore }
	rmfStore.mu.RUnlock()

	// Check DB
	dbStatus := "ok"
	if p4SQLDB != nil {
		if err := p4SQLDB.Ping(); err != nil {
			dbStatus = "error" // don't leak DB error details
			log.Printf("[P4-HEALTH] DB ping failed: %v", err)
		}
	} else { dbStatus = "not configured" }

	status := HealthStatus{
		Status:  "ok",
		Version: "2.0.0",
		Uptime:  time.Since(p4StartTime).Round(time.Second).String(),
		P4: P4HealthDetail{
			Readiness: p4r, Achieved: p4a,
			ATOStatus: atoStatus, ConMon: conmon,
			LastUpdate: lastUp,
		},
		Services: map[string]string{
			"database": dbStatus,
			"p4_state": "ok",
			"pipeline": "ok",
			"alerts":   "ok",
		},
		System: SystemInfo{
			Goroutines: runtime.NumGoroutine(),
			MemAllocMB: ms.Alloc / 1024 / 1024,
			GOOS:       runtime.GOOS,
			GoVersion:  runtime.Version(),
		},
		Timestamp: time.Now(),
	}

	if dbStatus != "ok" && dbStatus != "not configured" {
		status.Status = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(status)
}
