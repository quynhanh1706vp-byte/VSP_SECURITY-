-- 038_webauthn_credentials.sql — store WebAuthn / FIDO2 / passkey
-- credentials per user. One user can register multiple authenticators
-- (a YubiKey, a phone passkey, a laptop platform key) for redundancy.
--
-- Schema design follows the W3C WebAuthn Level 3 spec storage
-- requirements:
--   • credential_id     — opaque blob from authenticator (≤1023 bytes)
--   • public_key        — COSE-encoded public key (CBOR bytes)
--   • sign_count        — replay protection counter (must increase)
--   • aaguid            — Authenticator Attestation GUID, identifies
--     the make/model of the authenticator (used for policy: "only
--     allow YubiKeys" etc).
--   • transports        — comma-separated hint set ("usb,nfc,ble")

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  credential_id   BYTEA NOT NULL,
  public_key      BYTEA NOT NULL,
  sign_count      BIGINT NOT NULL DEFAULT 0,
  aaguid          UUID,
  transports      TEXT NOT NULL DEFAULT '',
  -- User-assigned label so the credential management UI can show
  -- "YubiKey 5C", "iPhone Touch ID", etc.
  nickname        TEXT NOT NULL DEFAULT '',
  -- "platform" or "cross-platform" — comes from PublicKeyCredentialType
  attachment      TEXT NOT NULL DEFAULT '',
  -- Whether the authenticator confirmed user verification (UV bit set).
  -- Required for PRO tenants with high-assurance policy.
  user_verified   BOOL NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at    TIMESTAMPTZ,
  -- Soft-delete: revoked credentials remain to preserve audit history
  -- but cannot be used for login. The unique index excludes them so a
  -- replacement key can be enrolled with the same nickname.
  revoked_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_cred_id
  ON webauthn_credentials(credential_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_user
  ON webauthn_credentials(user_id, revoked_at)
  WHERE revoked_at IS NULL;

-- Session table for in-flight registration / authentication challenges.
-- Challenges are bound to a user-agent session and expire after 5 min.
CREATE TABLE IF NOT EXISTS webauthn_sessions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID,                 -- NULL during initial registration
  tenant_id       UUID NOT NULL,
  flow            TEXT NOT NULL CHECK (flow IN ('registration','authentication')),
  challenge       BYTEA NOT NULL,
  -- The full session blob from go-webauthn; we marshal as JSONB so
  -- library upgrades that add fields don't break us.
  session_blob    JSONB NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webauthn_sess_expires
  ON webauthn_sessions(expires_at);
