
CREATE TABLE IF NOT EXISTS software_assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname        VARCHAR(255) NOT NULL UNIQUE,
    os              VARCHAR(50),
    os_version      VARCHAR(255),
    arch            VARCHAR(20),
    total_software  INT DEFAULT 0,
    suspicious_count INT DEFAULT 0,
    eol_count       INT DEFAULT 0,
    crack_count     INT DEFAULT 0,
    risk_score      INT DEFAULT 0,
    risk_level      VARCHAR(20) DEFAULT 'clean',
    last_seen       TIMESTAMPTZ,
    agent_version   VARCHAR(20),
    report_json     JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS software_findings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname    VARCHAR(255) NOT NULL,
    name        VARCHAR(500) NOT NULL,
    version     VARCHAR(100),
    publisher   VARCHAR(500),
    sha256      VARCHAR(64),
    signed      BOOLEAN DEFAULT false,
    suspicious  BOOLEAN DEFAULT false,
    susp_reason TEXT,
    source      VARCHAR(50),
    resolved    BOOLEAN DEFAULT false,
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(hostname, name, version)
);
CREATE TABLE IF NOT EXISTS eol_database (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_name    VARCHAR(255) NOT NULL,
    vendor          VARCHAR(255),
    version_pattern VARCHAR(100),
    eol_date        DATE,
    status          VARCHAR(50) DEFAULT 'eol',
    source          VARCHAR(100),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO eol_database (product_name,vendor,version_pattern,eol_date,status,source) VALUES
('Windows XP','Microsoft','','2014-04-08','eol','manual'),
('Windows 7','Microsoft','','2020-01-14','eol','manual'),
('Windows 8.1','Microsoft','8.1','2023-01-10','eol','manual'),
('Windows Server 2008','Microsoft','','2020-01-14','eol','manual'),
('Microsoft Office 2010','Microsoft','2010','2020-10-13','eol','manual'),
('Microsoft Office 2013','Microsoft','2013','2023-04-11','eol','manual'),
('Internet Explorer','Microsoft','','2022-06-15','eol','manual'),
('Adobe Flash Player','Adobe','','2020-12-31','eol','manual'),
('Java SE 6','Oracle','6','2013-04-01','eol','manual'),
('Java SE 7','Oracle','7','2015-04-01','eol','manual'),
('PHP','PHP Group','7.4','2022-11-28','eol','endoflife.date'),
('PHP','PHP Group','8.0','2023-11-26','eol','endoflife.date'),
('Node.js','OpenJS','16','2023-09-11','eol','endoflife.date'),
('Python','PSF','2','2020-01-01','eol','endoflife.date'),
('MySQL','Oracle','5.7','2023-10-31','eol','endoflife.date'),
('OpenSSL','OpenSSL','1.1','2023-09-11','eol','endoflife.date'),
('MISA SME.NET 2019','MISA','2019','2022-12-31','eol','manual'),
('Fast Accounting 11','Fast','11','2021-06-01','eol','manual'),
('BKAV Pro 2018','BKAV','2018','2020-12-31','eol','manual')
ON CONFLICT DO NOTHING;
