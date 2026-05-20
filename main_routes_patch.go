// ─────────────────────────────────────────────────────────────────────────────
// ROUTES PATCH — thay thế block SW Inventory trong main.go
// Tìm comment: "// Software Inventory routes (read-only — under CSRF group)"
// Thay cả block đó bằng đoạn dưới đây.
// ─────────────────────────────────────────────────────────────────────────────

		// ── Software Inventory ─────────────────────────────────────────────
		swH := &handler.SoftwareInventoryHandler{DB: db}

		// Read-only — GET, dưới CSRF group (browser calls)
		r.Get("/api/v1/software-inventory",                   swH.ListAssets)
		r.Get("/api/v1/software-inventory/stats",             swH.GetStats)
		r.Get("/api/v1/software-inventory/eol-database",      swH.ListEOL)
		r.Get("/api/v1/software-inventory/cracks",            swH.ListCracks)
		r.Get("/api/v1/software-inventory/licenses",          swH.ListLicenses)
		r.Get("/api/v1/software-inventory/scan-history",      swH.ListScanHistory)
		r.Get("/api/v1/software-inventory/whitelist",         swH.ListWhitelist)
		r.Get("/api/v1/software-inventory/blacklist",         swH.ListBlacklist)
		r.Get("/api/v1/software-inventory/policy",            swH.GetPolicy)
		// QUAN TRỌNG: route tĩnh PHẢI đứng trước {hostname} wildcard
		r.Get("/api/v1/software-inventory/{hostname}",        swH.GetAsset)

		// Write — POST/DELETE, vẫn dưới CSRF group (browser mutations)
		r.Post("/api/v1/software-inventory/hash-check",       swH.HashCheck)
		r.Post("/api/v1/software-inventory/policy",           swH.SavePolicy)
		r.Post("/api/v1/software-inventory/{list_type}",      swH.AddToList)
		r.Delete("/api/v1/software-inventory/{list_type}/{id}", swH.RemoveFromList)

// ─────────────────────────────────────────────────────────────────────────────
// Giữ nguyên block agent ingest bên dưới (NO CSRF):
// ─────────────────────────────────────────────────────────────────────────────
	// ─── [H3.U-1] SW Risk Agent ingest — JWT auth, NO CSRF ──────────
	r.Group(func(r chi.Router) {
		r.Use(authMw)
		swIngestH := &handler.SoftwareInventoryHandler{DB: db}
		r.Post("/api/v1/software-inventory/report", swIngestH.ReceiveReport)
	})

// ─────────────────────────────────────────────────────────────────────────────
// BODY-READER SKIP LIST — thêm prefix mới vào dòng 657
// Tìm: strings.HasPrefix(r.URL.Path, "/api/swinv")
// Thêm dưới nó:
//   strings.HasPrefix(r.URL.Path, "/api/v1/software-inventory") ||
// ─────────────────────────────────────────────────────────────────────────────
