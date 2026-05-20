BEGIN;
CREATE TABLE IF NOT EXISTS sw_policy_list (
    id        SERIAL PRIMARY KEY,
    list_type TEXT NOT NULL CHECK (list_type IN ('whitelist','blacklist','warning')),
    name      TEXT NOT NULL,
    version   TEXT NOT NULL DEFAULT 'any',
    vendor    TEXT NOT NULL DEFAULT '',
    category  TEXT NOT NULL DEFAULT 'other',
    reason    TEXT NOT NULL DEFAULT '',
    hash      TEXT,
    added_by  TEXT NOT NULL DEFAULT 'system',
    added_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (list_type, name)
);
CREATE INDEX IF NOT EXISTS idx_swpl_type ON sw_policy_list(list_type);
CREATE INDEX IF NOT EXISTS idx_swpl_name ON sw_policy_list(name);

CREATE TABLE IF NOT EXISTS tenant_config (
    key        TEXT PRIMARY KEY,
    config     JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sw_licenses (
    id           SERIAL PRIMARY KEY,
    component    TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '',
    license      TEXT,
    license_type TEXT NOT NULL DEFAULT 'Unknown',
    in_sbom      BOOLEAN NOT NULL DEFAULT false,
    source       TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (component, version)
);

INSERT INTO sw_policy_list (list_type,name,version,vendor,category,reason) VALUES
  ('whitelist','nginx','>=1.18','nginx.org','utility','Approved web server'),
  ('whitelist','python','>=3.8','PSF','devtools','Dev standard'),
  ('whitelist','chrome','any','Google','browser','Corporate browser'),
  ('whitelist','nodejs','>=16','OpenJS','devtools','Dev toolchain'),
  ('whitelist','curl','any','haxx.se','utility','CLI tool'),
  ('blacklist','teamviewer','any','TeamViewer','utility','Remote access risk'),
  ('blacklist','*_crack','any','Unknown','other','Pirated software'),
  ('blacklist','*_keygen','any','Unknown','other','License bypass tool'),
  ('warning','log4j','any','Apache','utility','Monitor CVE-2021-44228'),
  ('warning','oracle_jdk','8','Oracle','devtools','Commercial license check')
ON CONFLICT (list_type,name) DO NOTHING;

INSERT INTO tenant_config (key,config) VALUES
  ('sw_policy','{"block_unauthorized":true,"crack_scan_on_ingest":true,"eol_alert":true,"gpl_enforcement":false,"vt_enrichment":false}')
ON CONFLICT (key) DO NOTHING;
COMMIT;
