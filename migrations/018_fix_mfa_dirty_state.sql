-- Migration 018: Fix MFA dirty state (users stuck in setup-but-not-verified)
--
-- Background:
--   store/users.go SetMFASecret() sets mfa_enabled=true immediately during
--   /auth/mfa/setup (before user confirms TOTP code via /auth/mfa/verify).
--   
--   When SERVER_ENV=production|staging, login handler rejects admin users
--   with (!mfa_enabled || !mfa_verified) → HTTP 403.
--   
--   Race condition: if admin calls /mfa/setup and their session expires
--   before /mfa/verify, they are locked out. mfa_enabled=true blocks them,
--   mfa_verified=false keeps them blocked, and they cannot log in to
--   complete verification.
--
-- Fix:
--   1. This migration resets rows with dirty state (enabled but not verified).
--   2. Code change (same PR) modifies SetMFASecret to stop setting
--      mfa_enabled=true. New ConfirmMFAEnabled() method sets both flags atomically
--      at /auth/mfa/verify success.
--
-- Impact:
--   Affected users must re-run /auth/mfa/setup. Their existing (unconfirmed)
--   TOTP secrets are destroyed — this is safe because they were never
--   activated (no codes have ever been verified against them).
--
-- Refs:
--   - THREAT_MODEL.md § E (MFA)
--   - handler/auth.go:109 (admin MFA enforcement gate)
--   - handler/mfa.go Setup/Verify flow

UPDATE users
SET mfa_enabled = false,
    mfa_secret = NULL
WHERE mfa_enabled = true
  AND mfa_verified = false;
