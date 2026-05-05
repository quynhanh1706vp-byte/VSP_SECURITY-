-- Agents table — track installed VSP agents on assets
CREATE TABLE IF NOT EXISTS agents (
    id            VARCHAR(40) PRIMARY KEY,           -- agent uuid
    hostname      VARCHAR(255) NOT NULL,
    os_family     VARCHAR(20),                       -- linux | windows | darwin
    os_version    VARCHAR(100),
    arch          VARCHAR(20),                       -- x86_64 | arm64
    asset_id      VARCHAR(40),                       -- FK to assets when matched
    api_key_hash  VARCHAR(128) NOT NULL,             -- sha256 of API key (never store plaintext)
    api_key_hint  VARCHAR(8),                        -- last 4 chars for UI display
    enrolled_at   TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ,
    last_ip       INET,
    status        VARCHAR(20) DEFAULT 'active',      -- active | revoked | stale
    version       VARCHAR(20),                       -- agent version
    UNIQUE(api_key_hash)
);

CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents(hostname);
CREATE INDEX IF NOT EXISTS idx_agents_status   ON agents(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_agents_seen     ON agents(last_seen_at DESC);

-- Software inventory (per-agent, time-series)
CREATE TABLE IF NOT EXISTS software_packages (
    id            BIGSERIAL PRIMARY KEY,
    agent_id      VARCHAR(40) REFERENCES agents(id) ON DELETE CASCADE,
    name          VARCHAR(255) NOT NULL,
    version       VARCHAR(100),
    package_mgr   VARCHAR(20),                       -- dpkg | rpm | brew | choco | msi
    architecture  VARCHAR(20),
    install_date  TIMESTAMPTZ,
    reported_at   TIMESTAMPTZ DEFAULT NOW(),
    cve_matched   TEXT[],                            -- populated by background job
    UNIQUE(agent_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_pkg_agent ON software_packages(agent_id);
CREATE INDEX IF NOT EXISTS idx_pkg_name  ON software_packages(name, version);
CREATE INDEX IF NOT EXISTS idx_pkg_cve   ON software_packages USING GIN(cve_matched);

-- Audit table for inventory submissions
CREATE TABLE IF NOT EXISTS inventory_reports (
    id           BIGSERIAL PRIMARY KEY,
    agent_id     VARCHAR(40) REFERENCES agents(id),
    received_at  TIMESTAMPTZ DEFAULT NOW(),
    package_count INT,
    bytes        INT,
    source_ip    INET,
    user_agent   TEXT
);

CREATE INDEX IF NOT EXISTS idx_invrep_agent_time ON inventory_reports(agent_id, received_at DESC);
