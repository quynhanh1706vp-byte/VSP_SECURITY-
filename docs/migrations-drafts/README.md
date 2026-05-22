# Draft migrations (not applied)

These SQL files were drafted as future feature scaffolding but were never
adopted into `internal/migrate/sql/` because:

- **agents.sql**: no tenant_id column (incompatible with multi-tenant model),
  no Go consumer code. Concept overlaps with future "endpoint agent" feature
  pending product spec.

- **schedules.sql**: schema overlaps with `scan_schedules` (migration 008,
  applied) and `conmon_schedules` (013, applied). Generic naming without
  tenant_id makes it unsuitable as-is.

Both files are kept here as references. To adopt:
1. Add `tenant_id UUID NOT NULL` to all tables
2. Verify there's no concept collision with existing tables
3. Add a Go consumer (handler + store + routes) before applying
4. Bump migration number into `internal/migrate/sql/` with proper goose comments
