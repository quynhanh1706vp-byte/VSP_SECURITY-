package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/vsp/platform/internal/soar"
	"github.com/vsp/platform/internal/store"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://vsp:vsp@localhost:5432/vsp_go?sslmode=disable"
	}
	db, err := store.New(context.Background(), dsn)
	if err != nil {
		fmt.Println("ERR connect:", err)
		os.Exit(1)
	}
	defer db.Close()

	// Setup engine với store adapter
	adapter := &soar.StoreAdapter{DB: db}
	disp := soar.NewDispatcher()
	disp.RegisterDefault()
	soar.RegisterIOExecutors(disp, soar.NewSafeHTTPClient(), nil, nil)
	soar.RegisterFlowExecutors(disp, soar.NewSandbox(), nil, nil)

	eng, err := soar.New(soar.EngineConfig{
		Store:      adapter,
		Dispatcher: disp,
	})
	if err != nil {
		fmt.Println("ERR engine:", err)
		os.Exit(1)
	}
	mgr := soar.NewManager(eng, adapter)

	// Run "Gate FAIL auto-response" in test mode
	tenantID := "1bdf7f20-dbb3-4116-815f-26b4dc747e76"
	pbID := "2e040fa6-fc31-4e52-99d3-92769c03123a"

	run, err := mgr.ExecuteByID(context.Background(), tenantID, pbID, soar.ExecuteOptions{
		IsTest:      true,
		Context:     map[string]any{"gate": "FAIL", "severity": "HIGH"},
		TriggeredBy: "smoke",
	})
	if err != nil {
		fmt.Println("ERR execute:", err)
		os.Exit(1)
	}

	fmt.Printf("Run ID:   %s\n", run.ID)
	fmt.Printf("Status:   %s\n", run.Status)
	fmt.Printf("Steps:    %d\n", len(run.StepResults))
	fmt.Printf("Duration: %d ms\n", run.DurationMS)

	if run.Error != "" {
		fmt.Println("Error:", run.Error)
	}

	for i, sr := range run.StepResults {
		fmt.Printf("  [%d] %-20s (%-10s) %-10s %d ms\n",
			i, sr.NodeID, sr.Type, sr.Status, sr.DurationMS)
	}

	out, _ := json.MarshalIndent(run.StepResults, "", "  ")
	fmt.Println("\n────── Step details ──────")
	fmt.Println(string(out))
}
