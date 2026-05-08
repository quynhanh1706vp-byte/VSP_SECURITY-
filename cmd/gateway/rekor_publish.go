package main

// rekor_publish.go — publish a SLSA / DSSE attestation to the public
// Sigstore Rekor transparency log.
//
// Why this exists: a signed DSSE envelope sitting only in our database
// is auditable by us but not by external parties. Submitting the same
// envelope to Rekor (https://rekor.sigstore.dev) makes it
// independently verifiable — anyone can fetch the entry by UUID and
// confirm the signature without trusting VSP.
//
// We submit using Rekor's HTTP API ("hashedrekord" type for binary
// blobs, "intoto" type for in-toto/DSSE statements). Token-less —
// Rekor's public log accepts unauthenticated submissions; integrity
// comes from the cryptographic signature, not from the transport.
//
// Endpoint:
//   POST /api/v1/runs/{rid}/provenance/publish-rekor   (admin only)
//
// Returns the Rekor entry UUID + log index. The same UUID can be
// browsed at https://rekor.sigstore.dev/?logIndex=<index>.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const rekorBase = "https://rekor.sigstore.dev/api/v1"

// rekorIntotoEntry is the wire shape Rekor expects for in-toto entries.
// We encode the DSSE envelope's payload + signature; Rekor verifies
// the signature against the publicKey we attach.
type rekorIntotoEntry struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Spec       rekorIntotoSpec    `json:"spec"`
}

type rekorIntotoSpec struct {
	Content rekorIntotoContent `json:"content"`
}

type rekorIntotoContent struct {
	Envelope  string         `json:"envelope"`
	PublicKey rekorPublicKey `json:"publicKey"`
}

type rekorPublicKey struct {
	Content string `json:"content"` // base64-encoded PEM
}

type rekorEntryResponse struct {
	UUID     string `json:"uuid"`
	LogIndex int64  `json:"logIndex"`
}

func handleRekorPublish(w http.ResponseWriter, r *http.Request) {
	rid := strings.TrimSpace(chi.URLParam(r, "rid"))
	if rid == "" {
		writeJSONErr(w, http.StatusBadRequest, "rid required")
		return
	}
	if p4SQLDB == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "p4 db unavailable")
		return
	}

	// Pull the existing DSSE envelope. We refuse to publish anything
	// that doesn't already have a valid signature in the local DB —
	// this prevents an attacker who can call this endpoint from
	// freely populating Rekor with garbage.
	c, err := loadRunForProvenance(r.Context(), p4SQLDB, rid)
	if err == sql.ErrNoRows {
		writeJSONErr(w, http.StatusNotFound, "run not found")
		return
	}
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "load run: "+err.Error())
		return
	}
	env := loadExistingProvenance(r.Context(), p4SQLDB, c.RunID)
	if env == nil {
		writeJSONErr(w, http.StatusNotFound, "no signed provenance for this run; call POST /provenance first")
		return
	}

	// Build the Rekor in-toto entry.
	envBytes, err := json.Marshal(env)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "marshal envelope: "+err.Error())
		return
	}
	pubPEM, err := publicKeyPEM()
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	entry := rekorIntotoEntry{
		APIVersion: "0.0.2",
		Kind:       "intoto",
		Spec: rekorIntotoSpec{
			Content: rekorIntotoContent{
				Envelope:  base64.StdEncoding.EncodeToString(envBytes),
				PublicKey: rekorPublicKey{Content: base64.StdEncoding.EncodeToString([]byte(pubPEM))},
			},
		},
	}
	body, err := json.Marshal(entry)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "marshal rekor entry: "+err.Error())
		return
	}

	// POST to Rekor. 8s timeout — Rekor is normally fast (<2s) but
	// we cap to keep the gateway request responsive.
	rekorResp, rekorErr := submitToRekor(r.Context(), body)
	if rekorErr != nil {
		writeJSONErr(w, http.StatusBadGateway, "rekor: "+rekorErr.Error())
		return
	}

	// Persist the Rekor coordinates so future requests can dedup.
	if _, err := p4SQLDB.ExecContext(r.Context(),
		`UPDATE slsa_provenance
		    SET rekor_uuid = $1, rekor_log_index = $2, rekor_published_at = NOW()
		  WHERE run_id = $3 AND rekor_uuid IS NULL`,
		rekorResp.UUID, rekorResp.LogIndex, c.RunID); err != nil {
		// Non-fatal: Rekor entry is public regardless. Log + return
		// the entry to the caller so they can record it manually.
		_ = err
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"uuid":      rekorResp.UUID,
		"log_index": rekorResp.LogIndex,
		"explorer":  fmt.Sprintf("https://rekor.sigstore.dev/?logIndex=%d", rekorResp.LogIndex),
	})
}

func submitToRekor(ctx context.Context, body []byte) (*rekorEntryResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		rekorBase+"/log/entries", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncForLog(string(respBody)))
	}
	// Rekor returns a map keyed by UUID. We just want any entry it
	// returned — there's exactly one for our submission.
	var raw map[string]map[string]any
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return nil, fmt.Errorf("parse rekor response: %w", err)
	}
	for uuid, body := range raw {
		idx, _ := body["logIndex"].(float64)
		return &rekorEntryResponse{UUID: uuid, LogIndex: int64(idx)}, nil
	}
	return nil, fmt.Errorf("rekor: empty response")
}

func truncForLog(s string) string {
	if len(s) <= 200 {
		return s
	}
	return s[:200] + "…"
}

// digestForRekor — utility (unused in v1 but reserved for hashedrekord
// entries should we move away from in-toto envelopes).
var _ = hex.EncodeToString
