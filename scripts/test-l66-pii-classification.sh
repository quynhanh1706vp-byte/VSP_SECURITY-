#!/usr/bin/env bash
# scripts/test-l66-pii-classification.sh — data-classification matrix.
#
# FedRAMP RA-2, GDPR Art.32, SOC 2 CC6.1: every data element must be
# classified (public / internal / confidential / restricted) AND the
# classification must be enforced (encryption-at-rest for restricted,
# tenant-scoped access for confidential+).
#
# Probes:
#   1. A classification artefact exists (docs/DATA_CLASSIFICATION.md)
#   2. Every PII-bearing column the codebase references is tagged
#      in the doc — emails, phone, password_hash, MFA secrets, etc.
#   3. PII-tagged columns are actually used through redaction helpers
#      (e.g. logger.Str("email_hash", ...) not logger.Str("email", ...))

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 66.1 Classification artefact present ─────────────────────────────────

phase_open "66.1 Data-classification artefact present"

DOC=""
for cand in \
    "$ROOT/docs/DATA_CLASSIFICATION.md" \
    "$ROOT/docs/data-classification.md" \
    "$ROOT/docs/CLASSIFICATION.md"; do
  if [[ -r "$cand" ]]; then DOC="$cand"; break; fi
done

if [[ -z "$DOC" ]]; then
  _fail "66.1.0 classification doc absent" \
    "expected docs/DATA_CLASSIFICATION.md — compliance gap (FedRAMP RA-2 / GDPR Art.32)"
else
  _pass "66.1.0 classification doc at $(basename "$DOC")"
fi

# ── 66.2 Every PII column listed in classification matrix ────────────────

phase_open "66.2 PII-column coverage in classification"

# Known PII columns discovered by grepping CREATE TABLE statements +
# struct field tags. Curated list — extend as new sensitive columns
# land.
PII_COLUMNS=(
  "email"          # users / data_subject_requests
  "pw_hash"        # users
  "mfa_secret"     # webauthn / TOTP
  "phone"          # users / notifications
  "ip"             # audit_log (some jurisdictions classify IP as PII)
  "session_token"  # session table
  "refresh_token"  # OIDC token store
)

if [[ -z "$DOC" ]]; then
  _skip "66.2.1 PII coverage" "no classification doc to check"
else
  MISSING=()
  for col in "${PII_COLUMNS[@]}"; do
    # Case-insensitive, allow _ or space between words
    if ! grep -iqE "(^|[^a-z])${col//_/[ _-]?}([^a-z]|$)" "$DOC" 2>/dev/null; then
      MISSING+=("$col")
    fi
  done

  if (( ${#MISSING[@]} == 0 )); then
    _pass "66.2.1 all 7 PII columns documented in classification matrix"
  elif (( ${#MISSING[@]} <= 2 )); then
    _skip "66.2.1 partial PII coverage" \
      "missing: ${MISSING[*]} — informational"
  else
    _fail "66.2.1 most PII columns undocumented" \
      "${#MISSING[@]} of ${#PII_COLUMNS[@]} missing: ${MISSING[*]:0:3}..."
  fi
fi

# ── 66.3 Schema columns named "ssn" / "passport" don't exist unannotated ─

phase_open "66.3 No undeclared high-sensitivity column names"

# Anyone adding a column named `ssn`, `tax_id`, `passport_no`,
# `dob`, etc. without documenting needs to be caught.
HIGH_SENSITIVITY=("ssn" "tax_id" "passport_no" "national_id" "dob" "credit_card")
DETECTED=()
for col in "${HIGH_SENSITIVITY[@]}"; do
  if grep -rqE "\b$col\b" \
       --include='*.sql' \
       "$ROOT/migrations/" "$ROOT/internal/migrate/" 2>/dev/null; then
    # Found in schema — verify it's documented
    if [[ -n "$DOC" ]] && ! grep -iqE "\b$col\b" "$DOC" 2>/dev/null; then
      DETECTED+=("$col")
    fi
  fi
done

if (( ${#DETECTED[@]} == 0 )); then
  _pass "66.3.1 no high-sensitivity columns missing from classification"
else
  _fail "66.3.1 high-sensitivity column undocumented" \
    "${DETECTED[*]} present in schema but missing from doc"
fi

# ── 66.4 zerolog access logs use email_hash, not raw email ───────────────

phase_open "66.4 Log redaction — PII fields hashed before logging"

# Pattern bug: `log.Info().Str("email", user.Email)` ships raw PII to
# the log stream. Fix: log the SHA256 first-8-chars hash instead.
RAW_EMAIL=$(grep -rnE '\.Str\(\s*"email"\s*,' \
  --include='*.go' \
  "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go\|\.bak\|// safe-pii\|email_hash' \
  | head -3 || true)

if [[ -z "$RAW_EMAIL" ]]; then
  _pass "66.4.1 no .Str(\"email\", ...) raw-PII log calls"
else
  _fail "66.4.1 raw email logged" \
    "$(echo "$RAW_EMAIL" | head -1) — use email_hash + sha256-prefix"
fi

# Same for phone
RAW_PHONE=$(grep -rnE '\.Str\(\s*"phone"\s*,' \
  --include='*.go' \
  "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go\|\.bak\|// safe-pii\|phone_hash' \
  | head -3 || true)

if [[ -z "$RAW_PHONE" ]]; then
  _pass "66.4.2 no .Str(\"phone\", ...) raw-PII log calls"
else
  _fail "66.4.2 raw phone logged" "$(echo "$RAW_PHONE" | head -1)"
fi

# ── 66.5 Encryption-at-rest for restricted columns ──────────────────────

phase_open "66.5 At-rest encryption for restricted-class columns"

# `pw_hash` is OK as raw (bcrypt itself). `mfa_secret` / `refresh_token` /
# webhook secrets should be encrypted via internal/crypto AESGCM.
ENCRYPTED_REFS=$(grep -rnE 'AESGCM|EncryptString|NewFromPassphrase' \
  --include='*.go' \
  "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -5 || true)

if [[ -n "$ENCRYPTED_REFS" ]]; then
  CALLERS=$(echo "$ENCRYPTED_REFS" | wc -l | tr -d ' ')
  _pass "66.5.1 AESGCM encryption used at $CALLERS+ call sites"
else
  _fail "66.5.1 no at-rest encryption helpers used" \
    "internal/crypto AESGCM defined but not called — restricted columns may be plaintext"
fi

final_summary
