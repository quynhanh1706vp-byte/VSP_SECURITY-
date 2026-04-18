package main

import "strings"

func init() {
	// Thêm tất cả API paths vào exempt list
	// CSRF chỉ cần cho browser form POST không có Authorization header
	csrfExemptRoutes = append(csrfExemptRoutes,
		"/api/v1/auth/token",
		"/api/v1/auth/login",
		"/api/v1/auth/logout",
		"/api/v1/", // exempt tất cả /api/v1/ paths
		"/api/p4/", // exempt tất cả /api/p4/ paths
	)
	_ = strings.HasPrefix // avoid unused import
}
