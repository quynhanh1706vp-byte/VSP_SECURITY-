package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
)

// ── Entry ─────────────────────────────────────────────────────────────────────

// Entry represents one immutable audit log row.
// StoredHash is read from DB; all other fields are used to recompute it.
type Entry struct {
	Seq      int64
	TenantID string
	UserID   string
	Action   string
	Resource string
	IP       string
	PrevHash string
	// StoredHash is the hash written in the DB row — not used in Hash()
	StoredHash string
}

// ── Hash ──────────────────────────────────────────────────────────────────────

// Hash computes the canonical SHA-256 for an entry.
// Format: "seq|tenant_id|action|resource|prev_hash"
// This format MUST remain stable forever — changing it breaks chain verify.
func Hash(e Entry) string {
	raw := fmt.Sprintf("%d|%s|%s|%s|%s",
		e.Seq, e.TenantID, e.Action, e.Resource, e.PrevHash)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

// ── Store interface ───────────────────────────────────────────────────────────

// Store is implemented by the PostgreSQL store layer.
type Store interface {
	// ListAuditByTenant returns all audit entries for a tenant in ascending seq order.
	ListAuditByTenant(ctx context.Context, tenantID string) ([]Entry, error)

	// WriteAudit appends one entry and returns the assigned seq number.
	// The implementation MUST compute Hash(e) and store it in the hash column.
	WriteAudit(ctx context.Context, e Entry) (int64, error)
}

// ── Verify ────────────────────────────────────────────────────────────────────

// VerifyResult is returned by Verify.
type VerifyResult struct {
	OK          bool
	Checked     int
	BrokenAtSeq int64
	Err         error
}

// Verify walks all audit entries for a tenant and validates the hash chain.
// Returns VerifyResult with OK=true if the entire chain is intact.
func Verify(ctx context.Context, store Store, tenantID string) VerifyResult {
	entries, err := store.ListAuditByTenant(ctx, tenantID)
	if err != nil {
		return VerifyResult{Err: fmt.Errorf("audit verify: list entries: %w", err)}
	}

	for i, e := range entries {
		expected := Hash(e)
		if expected != e.StoredHash {
			return VerifyResult{
				OK:          false,
				Checked:     i,
				BrokenAtSeq: e.Seq,
				Err: fmt.Errorf("chain broken at seq %d: expected %s, got %s",
					e.Seq, expected, e.StoredHash),
			}
		}
		if i > 0 && e.PrevHash != entries[i-1].StoredHash {
			return VerifyResult{
				OK:          false,
				Checked:     i,
				BrokenAtSeq: e.Seq,
				Err:         fmt.Errorf("prev_hash mismatch at seq %d", e.Seq),
			}
		}
	}

	return VerifyResult{OK: true, Checked: len(entries)}
}

// ── Write ─────────────────────────────────────────────────────────────────────

// Write appends a new audit entry, computing the hash from the previous entry's hash.
// prevHash should be the StoredHash of the most recent entry for this tenant,
// or empty string for the first entry.
func Write(ctx context.Context, store Store, e Entry, prevHash string) (int64, error) {
	e.PrevHash = prevHash
	e.StoredHash = Hash(e)
	return store.WriteAudit(ctx, e)
}

// ── Repair ────────────────────────────────────────────────────────────────────

// Repairer is the optional interface a Store can implement to support chain
// repair. UpdateAuditHashes rewrites the prev_hash + hash columns for the
// given entries (in the order provided). It must be transactional.
type Repairer interface {
	UpdateAuditHashes(ctx context.Context, tenantID string, entries []Entry) error
}

// RepairResult is returned by RepairChain. RepairedFromSeq is the first seq
// where divergence was detected; entries from there onward had their hashes
// rewritten to restore chain continuity. The caller is expected to write a
// follow-up CHAIN_REPAIRED audit entry recording who initiated the repair.
type RepairResult struct {
	BrokenAtSeq    int64
	EntriesScanned int
	EntriesFixed   int
	NewTipHash     string
	DryRun         bool
}

// RepairChain finds the first divergence in the hash chain and rewrites all
// entries from there forward with recomputed hashes. The original entry data
// (action, resource, ip, etc.) is preserved — only the cryptographic chain is
// re-anchored. Use dryRun=true to preview without committing.
//
// Compliance note (FedRAMP AU-9, NIST 800-53): chain repair MUST itself be
// audited. Caller writes a CHAIN_REPAIRED entry with broken_at_seq + actor
// AFTER this returns successfully. Rebuilding tampered audit logs without
// recording the rebuild is itself a violation.
func RepairChain(ctx context.Context, store Store, tenantID string, dryRun bool) (RepairResult, error) {
	entries, err := store.ListAuditByTenant(ctx, tenantID)
	if err != nil {
		return RepairResult{}, fmt.Errorf("repair: list entries: %w", err)
	}
	if len(entries) == 0 {
		return RepairResult{DryRun: dryRun}, nil
	}

	// Find first divergence
	breakIdx := -1
	for i, e := range entries {
		expected := Hash(e)
		if expected != e.StoredHash {
			breakIdx = i
			break
		}
		if i > 0 && e.PrevHash != entries[i-1].StoredHash {
			breakIdx = i
			break
		}
	}

	res := RepairResult{
		EntriesScanned: len(entries),
		DryRun:         dryRun,
	}
	if breakIdx == -1 {
		// Chain intact — nothing to repair
		if len(entries) > 0 {
			res.NewTipHash = entries[len(entries)-1].StoredHash
		}
		return res, nil
	}

	res.BrokenAtSeq = entries[breakIdx].Seq

	// Rebuild from the break point. The previous entry (if any) is the anchor.
	var prevHash string
	if breakIdx > 0 {
		prevHash = entries[breakIdx-1].StoredHash
	}
	rebuilt := make([]Entry, 0, len(entries)-breakIdx)
	for i := breakIdx; i < len(entries); i++ {
		e := entries[i]
		e.PrevHash = prevHash
		e.StoredHash = Hash(e)
		rebuilt = append(rebuilt, e)
		prevHash = e.StoredHash
	}
	res.EntriesFixed = len(rebuilt)
	res.NewTipHash = prevHash

	if dryRun {
		return res, nil
	}

	rep, ok := store.(Repairer)
	if !ok {
		return res, fmt.Errorf("repair: store does not implement Repairer interface")
	}
	if err := rep.UpdateAuditHashes(ctx, tenantID, rebuilt); err != nil {
		return res, fmt.Errorf("repair: update hashes: %w", err)
	}
	return res, nil
}
