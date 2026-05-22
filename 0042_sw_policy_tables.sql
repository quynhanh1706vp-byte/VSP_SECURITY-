-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 0042: SW Policy tables
-- Tạo: sw_policy_list (whitelist/blacklist/warning), tenant_config
-- Depends: software_findings (từ migration trước)
-- Apply: psql $DATABASE_URL -f 0042_sw_policy_tables.sql
-- ─────────────────────────────────────────────────────────────────────────────

BEGIN;

-- ── sw_policy_list ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sw_policy_list (
    id         SERIAL PRIMARY KEY,
    list_type  TEXT    NOT NULL CHECK (list_type IN ('whitelist','blacklist','warning')),
    name       TEXT    NOT NULL,
    version    TEXT    NOT NULL DEFAULT 'any',
    vendor     TEXT    NOT NULL DEFAULT '',
    category   TEXT    NOT NULL DEFAULT 'other',
    reason     TEXT    NOT NULL DEFAULT '',
    hash       TEXT,                          -- optional known-good SHA-256
    added_by   TEXT    NOT NULL DEFAULT 'system',
    added_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- một package chỉ được có 1 entry per list_type
    UNIQUE (list_type, name)
);

CREATE INDEX IF NOT EXISTS idx_sw_policy_list_type ON sw_policy_list(list_type);
CREATE INDEX IF NOT EXISTS idx_sw_policy_list_name ON sw_policy_list(name);

-- ── tenant_config (generic KV store cho config nhỏ) ──────────────────────────
CREATE TABLE IF NOT EXISTS tenant_config (
    key        TEXT PRIMARY KEY,
    config     JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── sw_licenses (populate từ SBOM ingest / trivy) ────────────────────────────
-- Handler ListLicenses fallback gracefully nếu bảng chưa có data,
-- nhưng bảng cần tồn tại để tránh lỗi query.
CREATE TABLE IF NOT EXISTS sw_licenses (
    id           SERIAL PRIMARY KEY,
    component    TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '',
    license      TEXT,
    license_type TEXT NOT NULL DEFAULT 'Unknown', -- Permissive, Copyleft, Commercial, Unknown
    in_sbom      BOOLEAN NOT NULL DEFAULT false,
    source       TEXT,                             -- sbom file / scan run
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (component, version)
);

CREATE INDEX IF NOT EXISTS idx_sw_licenses_component ON sw_licenses(component);
CREATE INDEX IF NOT EXISTS idx_sw_licenses_license   ON sw_licenses(license);

-- ── Seed whitelist mặc định (có thể xoá nếu không cần) ───────────────────────
INSERT INTO sw_policy_list (list_type, name, version, vendor, category, reason, added_by) VALUES
  ('whitelist', 'nginx',       '>=1.18',  'nginx.org',      'utility',     'Approved web server',      'system'),
  ('whitelist', 'python',      '>=3.8',   'PSF',            'devtools',    'Dev standard',             'system'),
  ('whitelist', 'chrome',      'any',     'Google',         'browser',     'Corporate browser',        'system'),
  ('whitelist', 'nodejs',      '>=16',    'OpenJS',         'devtools',    'Dev toolchain',            'system'),
  ('whitelist', 'curl',        'any',     'haxx.se',        'utility',     'CLI tool',                 'system'),
  ('whitelist', 'libreoffice', 'any',     'TDF',            'productivity','Office suite',             'system'),
  ('whitelist', 'putty',       'any',     'Simon Tatham',   'utility',     'SSH client',               'system'),
  ('blacklist', 'teamviewer',  'any',     'TeamViewer',     'utility',     'Remote access risk',       'system'),
  ('blacklist', '*_crack',     'any',     'Unknown',        'other',       'Pirated software',         'system'),
  ('blacklist', '*_keygen',    'any',     'Unknown',        'other',       'License bypass tool',      'system'),
  ('blacklist', '*_patch',     'any',     'Unknown',        'other',       'Unauthorized patcher',     'system'),
  ('blacklist', 'utorrent',    'any',     'BitTorrent',     'utility',     'P2P — data exfil risk',    'system'),
  ('warning',   'log4j',       'any',     'Apache',         'utility',     'Monitor CVE-2021-44228',   'system'),
  ('warning',   'oracle_jdk',  '8',       'Oracle',         'devtools',    'Commercial license check', 'system'),
  ('warning',   'flash',       'any',     'Adobe',          'media',       'EOL — remove ASAP',        'system')
ON CONFLICT (list_type, name) DO NOTHING;

-- ── Default SW policy ─────────────────────────────────────────────────────────
INSERT INTO tenant_config (key, config) VALUES (
  'sw_policy',
  '{"block_unauthorized":true,"crack_scan_on_ingest":true,"eol_alert":true,"gpl_enforcement":false,"vt_enrichment":false}'
) ON CONFLICT (key) DO NOTHING;

COMMIT;
