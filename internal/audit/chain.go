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
				Err: fmt.Errorf("prev_hash mismatch at seq %d", e.Seq),
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
