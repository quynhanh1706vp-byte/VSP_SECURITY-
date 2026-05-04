// =====================================================================
// H3.S Auto-PR — HTTP Handlers
// File: internal/autopr/handlers.go
//
// Endpoints:
//   POST /api/v1/autofix/pr/create        manual PR creation (admin)
//   GET  /api/v1/autofix/pr/list          list PRs (filterable)
//   GET  /api/v1/autofix/pr/{id}/status   refresh status from provider
//   POST /api/v1/autofix/repo/register    register a repo (admin only)
//   POST /api/v1/autofix/pr/webhook/{repoID}  receive PR events
// =====================================================================

package autopr

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// =====================================================================
// HandlerCreatePR — manual PR creation
// =====================================================================

func HandlerCreatePR(db *sql.DB) http.HandlerFunc {
	svc := NewPRService(db)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var body struct {
			CacheKey     string `json:"cache_key"`
			FindingID    string `json:"finding_id"`
			RepoConfigID string `json:"repo_config_id"`
			BaseBranch   string `json:"base_branch,omitempty"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if body.CacheKey == "" || body.RepoConfigID == "" {
			http.Error(w, "cache_key and repo_config_id required", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()

		actor := actorFromHeader(r)

		result, err := svc.Create(ctx, &CreatePRInput{
			CacheKey:     body.CacheKey,
			FindingID:    body.FindingID,
			RepoConfigID: body.RepoConfigID,
			TriggerType:  "manual",
			CreatedBy:    actor,
			BaseBranch:   body.BaseBranch,
		})
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"error":   err.Error(),
				"trigger": "manual",
			})
			return
		}
		writeJSON(w, http.StatusCreated, result)
	}
}

// =====================================================================
// HandlerListPR — filterable list
// =====================================================================

func HandlerListPR(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()

		// Filter params
		status := r.URL.Query().Get("status")
		limit := parseIntDefault(r.URL.Query().Get("limit"), 50)
		if limit > 200 {
			limit = 200
		}

		args := []any{}
		where := []string{"1=1"}
		if status != "" {
			args = append(args, status)
			where = append(where, fmt.Sprintf("pr_status = $%d", len(args)))
		}
		args = append(args, limit)

		q := fmt.Sprintf(`
			SELECT id, cache_key, finding_id, COALESCE(rule_id,''), COALESCE(severity,''),
			       COALESCE(file_path,''), COALESCE(branch_name,''),
			       COALESCE(pr_number,0), COALESCE(pr_url,''),
			       pr_status, COALESCE(error_msg,''),
			       created_by, trigger_type, COALESCE(validation_score,0),
			       created_at, COALESCE(merged_at, '0001-01-01 00:00:00+00')
			FROM autofix_pr
			WHERE %s
			ORDER BY created_at DESC
			LIMIT $%d`, strings.Join(where, " AND "), len(args))

		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type prItem struct {
			ID              int64     `json:"id"`
			CacheKey        string    `json:"cache_key"`
			FindingID       string    `json:"finding_id"`
			RuleID          string    `json:"rule_id"`
			Severity        string    `json:"severity"`
			FilePath        string    `json:"file_path"`
			BranchName      string    `json:"branch_name"`
			PRNumber        int       `json:"pr_number"`
			PRURL           string    `json:"pr_url"`
			Status          string    `json:"status"`
			ErrorMsg        string    `json:"error_msg,omitempty"`
			CreatedBy       string    `json:"created_by"`
			TriggerType     string    `json:"trigger_type"`
			ValidationScore int       `json:"validation_score"`
			CreatedAt       time.Time `json:"created_at"`
			MergedAt        time.Time `json:"merged_at,omitempty"`
		}
		out := []prItem{}
		for rows.Next() {
			var p prItem
			if err := rows.Scan(&p.ID, &p.CacheKey, &p.FindingID, &p.RuleID,
				&p.Severity, &p.FilePath, &p.BranchName, &p.PRNumber, &p.PRURL,
				&p.Status, &p.ErrorMsg, &p.CreatedBy, &p.TriggerType,
				&p.ValidationScore, &p.CreatedAt, &p.MergedAt,
			); err != nil {
				continue
			}
			out = append(out, p)
		}

		// Summary stats
		var stats struct {
			Pending  int `json:"pending"`
			Created  int `json:"created"`
			Merged   int `json:"merged"`
			Closed   int `json:"closed"`
			Failed   int `json:"failed"`
			Conflict int `json:"conflict"`
		}
		_ = db.QueryRowContext(ctx, `
			SELECT
			  COUNT(*) FILTER (WHERE pr_status IN ('pending','creating')),
			  COUNT(*) FILTER (WHERE pr_status = 'created'),
			  COUNT(*) FILTER (WHERE pr_status = 'merged'),
			  COUNT(*) FILTER (WHERE pr_status = 'closed'),
			  COUNT(*) FILTER (WHERE pr_status = 'failed'),
			  COUNT(*) FILTER (WHERE pr_status = 'conflict')
			FROM autofix_pr
			WHERE created_at > NOW() - INTERVAL '30 days'`).
			Scan(&stats.Pending, &stats.Created, &stats.Merged,
				&stats.Closed, &stats.Failed, &stats.Conflict)

		writeJSON(w, http.StatusOK, map[string]any{
			"prs":          out,
			"count":        len(out),
			"summary_30d":  stats,
			"generated_at": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// =====================================================================
// HandlerPRStatus — refresh from provider
// =====================================================================

func HandlerPRStatus(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// /api/v1/autofix/pr/{id}/status
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/autofix/pr/")
		idStr := strings.TrimSuffix(path, "/status")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		// Load PR + linked repo config
		var (
			repoID, owner, repoName, platform, apiURL string
			tokenEnc                                  []byte
			prNumber                                  int
			currentStatus                             string
		)
		err = db.QueryRowContext(ctx, `
			SELECT rc.id::text, rc.repo_owner, rc.repo_name, rc.platform,
			       COALESCE(rc.api_url,''), rc.token_encrypted,
			       COALESCE(p.pr_number, 0), p.pr_status
			FROM autofix_pr p
			JOIN repo_config rc ON rc.id = p.repo_config_id
			WHERE p.id = $1`, id).
			Scan(&repoID, &owner, &repoName, &platform, &apiURL, &tokenEnc, &prNumber, &currentStatus)
		if err != nil {
			http.Error(w, "PR not found", http.StatusNotFound)
			return
		}
		if prNumber == 0 {
			writeJSON(w, http.StatusOK, map[string]any{
				"id":      id,
				"status":  currentStatus,
				"message": "PR has no number yet (not pushed to remote)",
			})
			return
		}

		svc := NewPRService(db)
		token, err := svc.decryptToken(tokenEnc)
		if err != nil {
			http.Error(w, "decrypt", http.StatusInternalServerError)
			return
		}
		defer zeroString(&token)

		provider, err := ProviderFor(platform, apiURL, token)
		if err != nil {
			http.Error(w, "provider error", http.StatusInternalServerError)
			return
		}
		pr, err := provider.GetPR(ctx, owner, repoName, prNumber)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"id": id, "error": err.Error(),
			})
			return
		}

		// Reconcile
		newStatus := mapProviderState(pr.State)
		if newStatus != "" && newStatus != currentStatus {
			updateCols := `pr_status = $1`
			args := []any{newStatus, id}
			if newStatus == "merged" {
				updateCols += `, merged_at = NOW()`
			} else if newStatus == "closed" {
				updateCols += `, closed_at = NOW()`
			}
			_, _ = db.ExecContext(ctx,
				fmt.Sprintf(`UPDATE autofix_pr SET %s WHERE id = $2`, updateCols),
				args...)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"id":             id,
			"pr_number":      pr.Number,
			"provider_state": pr.State,
			"local_status":   newStatus,
			"pr_url":         pr.HTMLURL,
		})
	}
}

func mapProviderState(s string) string {
	s = strings.ToLower(s)
	switch s {
	case "open":
		return "created"
	case "closed":
		return "closed" // could be merged, caller checks merged_at field separately
	case "merged":
		return "merged"
	}
	return ""
}

// =====================================================================
// HandlerRegisterRepo — admin registers a new repo target
// =====================================================================

func HandlerRegisterRepo(db *sql.DB) http.HandlerFunc {
	svc := NewPRService(db)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var body struct {
			TenantID       string   `json:"tenant_id,omitempty"`
			Nickname       string   `json:"nickname"`
			Platform       string   `json:"platform"`
			BaseURL        string   `json:"base_url"`
			APIURL         string   `json:"api_url,omitempty"`
			RepoOwner      string   `json:"repo_owner"`
			RepoName       string   `json:"repo_name"`
			DefaultBranch  string   `json:"default_branch,omitempty"`
			Token          string   `json:"token"`
			TokenUser      string   `json:"token_user"`
			AutoPREnabled  bool     `json:"auto_pr_enabled"`
			SLASeverity    []string `json:"sla_severity,omitempty"`
			SLAMinScore    int      `json:"sla_min_score,omitempty"`
			SLAMaxPerDay   int      `json:"sla_max_per_day,omitempty"`
			WebhookSecret  string   `json:"webhook_secret,omitempty"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if body.Platform == "" || body.BaseURL == "" || body.RepoOwner == "" ||
			body.RepoName == "" || body.Token == "" || body.TokenUser == "" {
			http.Error(w, "missing required fields", http.StatusBadRequest)
			return
		}
		if body.DefaultBranch == "" {
			body.DefaultBranch = "main"
		}
		if body.SLAMinScore == 0 {
			body.SLAMinScore = 80
		}
		if body.SLAMaxPerDay == 0 {
			body.SLAMaxPerDay = 10
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		encToken, err := svc.EncryptToken(body.Token)
		if err != nil {
			http.Error(w, "encrypt failed", http.StatusInternalServerError)
			return
		}

		var tenantArg any
		if body.TenantID != "" {
			tenantArg = body.TenantID
		}

		var newID string
		err = db.QueryRowContext(ctx, `INSERT INTO repo_config
			(tenant_id, nickname, platform, base_url, api_url,
			 repo_owner, repo_name, default_branch, token_encrypted, token_user,
			 auto_pr_enabled, sla_severity, sla_min_score, sla_max_per_day,
			 webhook_secret)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
			RETURNING id::text`,
			tenantArg, body.Nickname, body.Platform, body.BaseURL,
			nullIfEmpty(body.APIURL), body.RepoOwner, body.RepoName, body.DefaultBranch,
			encToken, body.TokenUser, body.AutoPREnabled,
			defaultSeverities(body.SLASeverity), body.SLAMinScore, body.SLAMaxPerDay,
			nullIfEmpty(body.WebhookSecret),
		).Scan(&newID)
		if err != nil {
			http.Error(w, "insert failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{
			"id":       newID,
			"nickname": body.Nickname,
			"platform": body.Platform,
			"repo":     fmt.Sprintf("%s/%s", body.RepoOwner, body.RepoName),
		})
	}
}

func defaultSeverities(in []string) any {
	if len(in) == 0 {
		// pq array literal
		return "{critical,high}"
	}
	cleaned := []string{}
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		if s != "" {
			cleaned = append(cleaned, s)
		}
	}
	return "{" + strings.Join(cleaned, ",") + "}"
}

// =====================================================================
// HandlerWebhook — receive PR events from provider
// =====================================================================

func HandlerWebhook(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Path: /api/v1/autofix/pr/webhook/{repo_config_id}
		repoID := strings.TrimPrefix(r.URL.Path, "/api/v1/autofix/pr/webhook/")
		if repoID == "" || len(repoID) > 64 {
			http.Error(w, "bad repo id", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		// Load webhook secret
		var secret string
		_ = db.QueryRowContext(ctx,
			`SELECT COALESCE(webhook_secret,'') FROM repo_config WHERE id::text = $1`,
			repoID).Scan(&secret)

		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		// Verify signature (GitHub-style: X-Hub-Signature-256: sha256=...)
		sigHeader := r.Header.Get("X-Hub-Signature-256")
		sigValid := verifyGitHubSignature(secret, body, sigHeader)

		// Always log webhook event (even if signature invalid — for security audit)
		event := r.Header.Get("X-GitHub-Event")
		delivery := r.Header.Get("X-GitHub-Delivery")
		payloadHash := sha256Hex(body)

		_, _ = db.ExecContext(ctx, `INSERT INTO autofix_pr_webhook
			(repo_config_id, event_type, delivery_id, signature_valid, payload_hash)
			VALUES ($1::uuid, $2, $3, $4, $5)`,
			repoID, event, delivery, sigValid, payloadHash)

		if !sigValid && secret != "" {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}

		// Parse payload (only need PR number + action + state)
		var p struct {
			Action      string `json:"action"`
			PullRequest struct {
				Number int    `json:"number"`
				State  string `json:"state"`
				Merged bool   `json:"merged"`
				HTMLURL string `json:"html_url"`
			} `json:"pull_request"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			// Not a PR event we care about
			w.WriteHeader(http.StatusOK)
			return
		}

		if p.PullRequest.Number > 0 {
			newStatus := ""
			switch {
			case p.PullRequest.Merged:
				newStatus = "merged"
			case p.Action == "closed" && p.PullRequest.State == "closed":
				newStatus = "closed"
			case p.Action == "opened" || p.Action == "reopened":
				newStatus = "created"
			}
			if newStatus != "" {
				cols := "pr_status = $1"
				args := []any{newStatus, p.PullRequest.Number, repoID}
				if newStatus == "merged" {
					cols += ", merged_at = NOW()"
				} else if newStatus == "closed" {
					cols += ", closed_at = NOW()"
				}
				_, _ = db.ExecContext(ctx,
					fmt.Sprintf(`UPDATE autofix_pr SET %s
					 WHERE pr_number = $2 AND repo_config_id = $3::uuid`, cols),
					args...)
			}
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
}

func verifyGitHubSignature(secret string, body []byte, sigHeader string) bool {
	if secret == "" {
		return true // no secret configured = accept (caller logs this)
	}
	if !strings.HasPrefix(sigHeader, "sha256=") {
		return false
	}
	provided := strings.TrimPrefix(sigHeader, "sha256=")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(provided), []byte(expected))
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// =====================================================================
// Common helpers
// =====================================================================

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func actorFromHeader(r *http.Request) string {
	if u := r.Header.Get("X-User"); u != "" {
		return u
	}
	if a := r.Header.Get("Authorization"); a != "" {
		return "token-user"
	}
	return "anonymous"
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// =====================================================================
// HandlerListRepos — list configured repos (no token returned)
// =====================================================================

func HandlerListRepos(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		rows, err := db.QueryContext(ctx, `
			SELECT id::text, COALESCE(tenant_id::text,''), nickname, platform,
			       repo_owner, repo_name, default_branch,
			       enabled, auto_pr_enabled,
			       COALESCE(sla_min_score, 80), COALESCE(sla_max_per_day, 10)
			FROM repo_config
			WHERE enabled = true
			ORDER BY nickname`)
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type repoItem struct {
			ID            string `json:"id"`
			TenantID      string `json:"tenant_id,omitempty"`
			Nickname      string `json:"nickname"`
			Platform      string `json:"platform"`
			RepoOwner     string `json:"repo_owner"`
			RepoName      string `json:"repo_name"`
			DefaultBranch string `json:"default_branch"`
			Enabled       bool   `json:"enabled"`
			AutoPREnabled bool   `json:"auto_pr_enabled"`
			SLAMinScore   int    `json:"sla_min_score"`
			SLAMaxPerDay  int    `json:"sla_max_per_day"`
		}
		out := []repoItem{}
		for rows.Next() {
			var ri repoItem
			if err := rows.Scan(&ri.ID, &ri.TenantID, &ri.Nickname, &ri.Platform,
				&ri.RepoOwner, &ri.RepoName, &ri.DefaultBranch,
				&ri.Enabled, &ri.AutoPREnabled, &ri.SLAMinScore, &ri.SLAMaxPerDay,
			); err != nil {
				continue
			}
			out = append(out, ri)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"repos": out,
			"count": len(out),
		})
	}
}
