-- 034_webhook_pinning.sql — outbound webhook SPKI pin storage.
--
-- Stores up to N base64-SHA256 pins per webhook target so the fan-out
-- worker can refuse to deliver to a host whose TLS leaf no longer matches
-- a registered key. The check is layered ON TOP of standard PKI, not
-- instead of it (we still verify the cert chain against system roots).
--
-- Format: comma-separated list of base64(SHA-256(SubjectPublicKeyInfo)).
-- Empty (NULL or '') = pinning disabled for this row, behaves like before.

ALTER TABLE siem_webhooks
  ADD COLUMN IF NOT EXISTS pinned_pubkey_sha256 TEXT NOT NULL DEFAULT '';

-- generic_webhook in notification_config also needs pinning capability
-- since some PRO panels deliver via that path. Keep the column nullable so
-- legacy rows don't break.
ALTER TABLE notification_config
  ADD COLUMN IF NOT EXISTS generic_webhook_pin TEXT NOT NULL DEFAULT '';
