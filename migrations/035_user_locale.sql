-- 035_user_locale.sql — per-user locale preference for i18n.
--
-- The middleware reads locale from query / header / Accept-Language at
-- each request, but authenticated users want their choice to persist
-- across browsers. This column lets the SPA fetch the saved locale at
-- login and emit X-VSP-Locale on subsequent requests.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS locale TEXT NOT NULL DEFAULT '';

-- '' means "no preference saved yet — fall through to header/Accept-Language".
