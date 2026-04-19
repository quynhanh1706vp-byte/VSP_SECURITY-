-- Migration 017: Incident Response + CIRCIA Reporting + Forensics
-- References:
--   NIST SP 800-61 Rev.3 — Computer Security Incident Handling Guide (April 2025)
--   NIST SP 800-184 — Cybersecurity Event Recovery
--   NIST SP 800-86 — Guide to Integrating Forensic Techniques
--   CIRCIA 2022 — Cyber Incident Reporting for Critical Infrastructure Act
--     Final rule expected May 2026 (CISA)
--     72-hour substantial incident reporting
--     24-hour ransomware payment reporting
--   EO 14028 — Improving the Nation's Cybersecurity

-- ═══ Incident tracking (NIST SP 800-61 Rev.3) ═══
CREATE TABLE IF NOT EXISTS ir_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    incident_id TEXT UNIQUE NOT NULL,           -- human-readable e.g. "INC-2026-0001"
    title TEXT NOT NULL,
    description TEXT,
    
    -- NIST SP 800-61 Rev.3 lifecycle phases
    phase TEXT NOT NULL DEFAULT 'detection' CHECK (phase IN (
        'preparation',
        'detection_analysis',
        'containment',
        'eradication',
        'recovery',
        'post_incident'
    )),
    
    -- Severity & classification
    severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN (
        'low','medium','high','critical'
    )),
    
    -- US-CERT / CISA incident categories (CAT 0-6)
    category TEXT CHECK (category IN (
        'CAT-0','CAT-1','CAT-2','CAT-3','CAT-4','CAT-5','CAT-6'
    )),
    -- CAT-0: Exercise, CAT-1: Unauthorized access, CAT-2: DoS,
    -- CAT-3: Malicious code, CAT-4: Improper usage, CAT-5: Scans/probes, CAT-6: Investigation
    
    -- CIRCIA flags
    is_substantial BOOL NOT NULL DEFAULT false,   -- Triggers 72h reporting
    is_ransomware BOOL NOT NULL DEFAULT false,    -- Triggers 24h reporting
    ransom_paid BOOL NOT NULL DEFAULT false,
    ransom_amount_usd NUMERIC(14,2),
    ransom_paid_at TIMESTAMPTZ,
    
    -- Impact assessment (CIRCIA substantial criteria)
    impact_confidentiality BOOL DEFAULT false,
    impact_integrity BOOL DEFAULT false,
    impact_availability BOOL DEFAULT false,
    impact_safety BOOL DEFAULT false,
    impact_business_ops BOOL DEFAULT false,
    impact_supply_chain BOOL DEFAULT false,
    
    -- Timeline
    detected_at TIMESTAMPTZ NOT NULL,
    confirmed_at TIMESTAMPTZ,
    contained_at TIMESTAMPTZ,
    eradicated_at TIMESTAMPTZ,
    recovered_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    
    -- People
    reporter TEXT,
    assigned_to TEXT,
    incident_commander TEXT,
    
    -- Tracking
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN (
        'open','investigating','contained','resolved','closed','false_positive'
    )),
    
    -- Lessons learned
    lessons_learned TEXT,
    root_cause TEXT,
    corrective_actions JSONB DEFAULT '[]'::jsonb,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ir_phase ON ir_incidents(phase);
CREATE INDEX IF NOT EXISTS idx_ir_severity ON ir_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_ir_status ON ir_incidents(status);
CREATE INDEX IF NOT EXISTS idx_ir_substantial ON ir_incidents(is_substantial) WHERE is_substantial = true;
CREATE INDEX IF NOT EXISTS idx_ir_ransomware ON ir_incidents(is_ransomware) WHERE is_ransomware = true;
CREATE INDEX IF NOT EXISTS idx_ir_detected ON ir_incidents(detected_at DESC);

-- ═══ CIRCIA Reports (72h / 24h reporting to CISA) ═══
CREATE TABLE IF NOT EXISTS circia_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    incident_id UUID REFERENCES ir_incidents(id) ON DELETE SET NULL,
    report_uuid TEXT UNIQUE NOT NULL,
    
    -- Report type
    report_type TEXT NOT NULL CHECK (report_type IN (
        'substantial_incident',      -- 72-hour report
        'ransomware_payment',        -- 24-hour report
        'supplemental',              -- updates to prior report
        'joint'                      -- combined incident + ransom
    )),
    
    -- Critical infrastructure sector (16 sectors per PPD-21)
    ci_sector TEXT CHECK (ci_sector IN (
        'chemical','commercial_facilities','communications','critical_manufacturing',
        'dams','defense_industrial_base','emergency_services','energy',
        'financial_services','food_agriculture','government_facilities',
        'healthcare_public_health','information_technology','nuclear',
        'transportation','water_wastewater'
    )),
    
    -- Deadline compliance
    incident_detected_at TIMESTAMPTZ NOT NULL,
    deadline_at TIMESTAMPTZ NOT NULL,            -- 72h or 24h from detected
    submitted_at TIMESTAMPTZ,
    deadline_met BOOL GENERATED ALWAYS AS (
        submitted_at IS NULL OR submitted_at <= deadline_at
    ) STORED,
    hours_elapsed NUMERIC(6,2),
    
    -- Report content (aligned with CIRCIA NPRM April 2024)
    narrative_description TEXT,
    affected_systems TEXT[],
    indicators_of_compromise JSONB DEFAULT '[]'::jsonb,
    threat_actor_info TEXT,
    attack_vector TEXT,
    vulnerabilities_exploited TEXT[],
    
    -- Ransomware-specific
    ransom_demand_amount_usd NUMERIC(14,2),
    ransom_paid_amount_usd NUMERIC(14,2),
    ransom_payment_method TEXT,                  -- crypto currency type, wire, etc.
    ransom_wallet_address TEXT,
    
    -- Status
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN (
        'draft','under_review','submitted','acknowledged','closed'
    )),
    
    -- CISA submission
    cisa_submission_id TEXT,                     -- CISA ack ref
    cisa_acknowledged_at TIMESTAMPTZ,
    
    -- Full report JSON
    report_json JSONB NOT NULL,
    
    -- Submitter
    submitted_by_name TEXT,
    submitted_by_title TEXT,
    submitted_by_email TEXT,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_circia_type ON circia_reports(report_type);
CREATE INDEX IF NOT EXISTS idx_circia_status ON circia_reports(status);
CREATE INDEX IF NOT EXISTS idx_circia_deadline ON circia_reports(deadline_at);
CREATE INDEX IF NOT EXISTS idx_circia_incident ON circia_reports(incident_id);

-- ═══ Forensics — Chain of Custody (NIST SP 800-86) ═══
CREATE TABLE IF NOT EXISTS forensics_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    incident_id UUID REFERENCES ir_incidents(id) ON DELETE CASCADE,
    evidence_id TEXT UNIQUE NOT NULL,            -- e.g. "EVD-2026-0001"
    
    -- Evidence description
    evidence_type TEXT NOT NULL CHECK (evidence_type IN (
        'memory_dump','disk_image','network_capture','log_file',
        'malware_sample','email','document','screenshot','other'
    )),
    description TEXT NOT NULL,
    
    -- File details
    file_path TEXT,                              -- storage path
    file_size_bytes BIGINT,
    file_hash_sha256 TEXT,
    
    -- Collection details
    collected_by TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    collection_method TEXT,                       -- "dd", "volatility", "tcpdump"
    source_system TEXT,
    
    -- Chain of custody events
    custody_log JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Format: [{"timestamp": "...", "actor": "...", "action": "...", "location": "..."}]
    
    -- Analysis
    analyzed BOOL NOT NULL DEFAULT false,
    analysis_findings TEXT,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_forensics_incident ON forensics_evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_forensics_type ON forensics_evidence(evidence_type);

-- ═══ IR Playbooks (NIST SP 800-61 Preparation phase) ═══
CREATE TABLE IF NOT EXISTS ir_playbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    incident_types TEXT[] NOT NULL,              -- what incidents this applies to
    phases JSONB NOT NULL,                       -- [{phase, steps}]
    last_exercised TIMESTAMPTZ,
    exercise_frequency_days INT DEFAULT 180,     -- semi-annual default
    author TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ═══ Seed IR Playbooks (5 common incident types) ═══
INSERT INTO ir_playbooks (playbook_id, name, description, incident_types, phases, author) VALUES
('PB-RANSOMWARE', 'Ransomware Attack Response',
 'Respond to ransomware encryption + payment demands. Meets CIRCIA 24h requirement if payment made.',
 ARRAY['ransomware','data_encryption'],
 '[
   {"phase":"preparation","steps":["Maintain offline backups","Test restore procedures quarterly","Subscribe to CISA StopRansomware alerts"]},
   {"phase":"detection_analysis","steps":["Identify encrypted systems","Preserve memory + disk images","Identify ransomware family (ID Ransomware)","Check decryption tools availability"]},
   {"phase":"containment","steps":["Isolate infected systems","Disable network shares","Disable scheduled tasks","Block C2 domains"]},
   {"phase":"eradication","steps":["Remove ransomware binaries","Patch exploited vulnerabilities","Reset credentials","Rebuild infected systems from clean backups"]},
   {"phase":"recovery","steps":["Restore from verified clean backups","Validate restored data integrity","Monitor for reinfection","Document downtime"]},
   {"phase":"post_incident","steps":["CIRCIA 72h report if substantial","CIRCIA 24h report if ransom paid","Root cause analysis","Update playbook"]}
 ]'::jsonb,
 'security@vsp.local'),

('PB-DATA-BREACH', 'Data Breach Response',
 'PII/PHI/CUI exposure — GDPR/HIPAA/CIRCIA/state breach laws.',
 ARRAY['data_exfiltration','unauthorized_access'],
 '[
   {"phase":"detection_analysis","steps":["Scope: what data, how much, whose","Preserve logs","Identify attack vector","Assess authentication trail"]},
   {"phase":"containment","steps":["Revoke compromised credentials","Block exfiltration endpoints","Force password reset affected users","Enable MFA on all accounts"]},
   {"phase":"eradication","steps":["Remove attacker access","Patch vulnerabilities","Rotate API keys, certs, secrets"]},
   {"phase":"recovery","steps":["Legal notification (GDPR 72h, state laws varies)","Customer notification","Credit monitoring offer if PII"]},
   {"phase":"post_incident","steps":["CIRCIA report","Regulatory filings (SEC 4-day if public co)","External PR response"]}
 ]'::jsonb,
 'security@vsp.local'),

('PB-SUPPLY-CHAIN', 'Supply Chain Compromise',
 'Compromised third-party components (SolarWinds/Log4j/XZ scenarios).',
 ARRAY['supply_chain','compromised_dependency'],
 '[
   {"phase":"detection_analysis","steps":["Consult SBOM for affected components","Check VEX statements","Review Sigstore signatures","Identify blast radius"]},
   {"phase":"containment","steps":["Pin to last-known-good version","Block malicious package downloads","Re-sign and re-verify artifacts"]},
   {"phase":"eradication","steps":["Remove compromised component","Deploy patched version","Rotate credentials used by compromised component"]},
   {"phase":"recovery","steps":["Rebuild affected artifacts","Re-attest SLSA provenance","Update SBOM"]},
   {"phase":"post_incident","steps":["File VEX for affected CVEs","CISA coordinated disclosure","Notify customers if SaaS"]}
 ]'::jsonb,
 'security@vsp.local'),

('PB-DOS-DDOS', 'Denial of Service Response',
 'Network/application layer DoS attacks.',
 ARRAY['denial_of_service'],
 '[
   {"phase":"detection_analysis","steps":["Identify attack vectors (L3/L4/L7)","Check CDN/WAF logs","Identify source IPs/ASNs"]},
   {"phase":"containment","steps":["Enable CDN/WAF","Rate limit","Block abusive IPs","Enable DDoS protection (AWS Shield etc.)"]},
   {"phase":"recovery","steps":["Scale up capacity","Restore normal operations"]},
   {"phase":"post_incident","steps":["Capture attack signatures","Update WAF rules","If substantial → CIRCIA report"]}
 ]'::jsonb,
 'security@vsp.local'),

('PB-INSIDER-THREAT', 'Insider Threat Response',
 'Malicious or negligent insider actions.',
 ARRAY['insider_threat','data_misuse'],
 '[
   {"phase":"detection_analysis","steps":["Review UEBA alerts","Preserve employee access logs","Coordinate with HR + Legal","Quietly collect evidence"]},
   {"phase":"containment","steps":["Revoke access (carefully)","Preserve workstation state","Document chain of custody"]},
   {"phase":"eradication","steps":["HR proceedings","Legal action if applicable","Update access reviews"]},
   {"phase":"post_incident","steps":["Background check process review","Privileged access audit","Training improvements"]}
 ]'::jsonb,
 'security@vsp.local')

ON CONFLICT (playbook_id) DO NOTHING;

-- ═══ Seed sample incidents (past) — CLOSED to show lifecycle ═══
INSERT INTO ir_incidents (
    incident_id, title, description, tenant_id, phase, severity, category,
    is_substantial, is_ransomware, detected_at, confirmed_at, contained_at,
    eradicated_at, recovered_at, closed_at, status,
    impact_integrity, impact_availability,
    lessons_learned, root_cause
) VALUES
('INC-2026-0001', 'Suspicious login attempts from TOR exit nodes',
 'Multiple failed authentication attempts from known TOR exit IPs targeting admin accounts',
 '1bdf7f20-dbb3-4116-815f-26b4dc747e76',
 'post_incident', 'medium', 'CAT-1',
 false, false,
 NOW() - INTERVAL '30 days', NOW() - INTERVAL '30 days' + INTERVAL '2 hours',
 NOW() - INTERVAL '29 days', NOW() - INTERVAL '28 days',
 NOW() - INTERVAL '27 days', NOW() - INTERVAL '25 days',
 'closed',
 false, false,
 'Rate limiting + GeoIP blocking prevented account takeover. MFA enforced.',
 'TOR anonymization used by threat actors for reconnaissance'),

('INC-2026-0002', 'Log4Shell exploitation attempt detected',
 'WAF detected attempted ${jndi:ldap://} injection in HTTP headers',
 '1bdf7f20-dbb3-4116-815f-26b4dc747e76',
 'post_incident', 'high', 'CAT-3',
 true, false,
 NOW() - INTERVAL '15 days', NOW() - INTERVAL '15 days' + INTERVAL '30 minutes',
 NOW() - INTERVAL '15 days' + INTERVAL '1 hour', NOW() - INTERVAL '14 days',
 NOW() - INTERVAL '14 days', NOW() - INTERVAL '10 days',
 'closed',
 false, false,
 'Log4j already patched to 2.17+. WAF rules updated. Subscribe to CVE-2021-44228 feed.',
 'Unpatched third-party library (mitigated, no exploitation)')

ON CONFLICT (incident_id) DO NOTHING;

COMMENT ON TABLE ir_incidents IS 'NIST SP 800-61 Rev.3 incident tracking — 6 lifecycle phases';
COMMENT ON TABLE circia_reports IS 'CIRCIA 2022 reporting — 72h substantial / 24h ransomware';
COMMENT ON TABLE forensics_evidence IS 'NIST SP 800-86 forensics with chain of custody';
COMMENT ON TABLE ir_playbooks IS 'IR playbooks per NIST SP 800-61 Preparation phase';

-- Verify
SELECT 'ir_incidents' AS tbl, COUNT(*) FROM ir_incidents
UNION ALL SELECT 'circia_reports', COUNT(*) FROM circia_reports
UNION ALL SELECT 'forensics_evidence', COUNT(*) FROM forensics_evidence
UNION ALL SELECT 'ir_playbooks', COUNT(*) FROM ir_playbooks;
