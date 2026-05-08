-- 029_notification_retry.sql — add retry/DLQ columns to notification_log so
-- transient webhook failures (5xx, timeouts, network blips) get re-attempted
-- instead of silently dropped. Closes the "webhook DLQ" gap reported in the
-- Sprint 2 DevSecOps audit.
--
-- Semantics after this migration:
--   status_code = 0   AND attempts = 0  → never tried, ready to deliver
--   status_code 2xx                     → delivered OK
--   status_code 4xx (except 408/429)    → permanent fail, do not retry
--   status_code 5xx OR 408/429 OR error → transient fail, retry until attempts >= max_attempts
--   attempts >= max_attempts            → moved to DLQ (status_code = -1)
--
-- The fanout worker filters by (next_retry_at IS NULL OR next_retry_at <= NOW())
-- so backoff schedule is encoded in the row itself, not in the worker.

ALTER TABLE notification_log
  ADD COLUMN IF NOT EXISTS attempts        INT  NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS max_attempts    INT  NOT NULL DEFAULT 5,
  ADD COLUMN IF NOT EXISTS next_retry_at   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ;

-- Index supports the fanout SELECT: pending or due-for-retry rows, ordered by
-- the earliest scheduled retry. Without this the worker scans the whole table
-- once notification_log grows past a few thousand rows.
CREATE INDEX IF NOT EXISTS notification_log_retry_idx
  ON notification_log (next_retry_at, sent_at)
  WHERE status_code = 0 OR (attempts > 0 AND attempts < max_attempts);
