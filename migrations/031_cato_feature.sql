-- 031_cato_feature.sql — register the cATO (continuous Authority To Operate)
-- toggle as a feature_config entry, and provide a tenant-level posture view
-- for the dashboard summary card.
--
-- cATO is a NIST RMF / DoD CIO posture where a system maintains an authority
-- to operate via continuous monitoring evidence rather than periodic 3-year
-- reauthorisation. Enabling the toggle for a tenant raises evidence
-- requirements (audit-chain integrity, drift acknowledgement SLA, automated
-- POA&M generation) — the FE panel surfaces these as required readiness
-- criteria.

ALTER TABLE feature_config
  DROP CONSTRAINT IF EXISTS feature_config_feature_id_check;

ALTER TABLE feature_config
  ADD CONSTRAINT feature_config_feature_id_check
  CHECK (feature_id IN (
    -- 12 SIEM panels (migration 026 originals)
    'ai_analyst', 'scheduler', 'correlation', 'soar',
    'log_ingestion', 'ueba', 'assets', 'sw_inventory',
    'network_flow', 'threat_hunt', 'vuln_mgmt', 'threat_intel',
    -- 7 REPORTS panels (Pass 1A iframe + Pass 1B inline)
    'analytics', 'executive', 'export',
    'users', 'cicd', 'integrations', 'settings',
    -- 7 Settings panel sub-tabs
    'settings_general', 'settings_scan', 'settings_alerts',
    'settings_apikeys', 'settings_security', 'settings_health',
    'settings_retention',
    -- Sprint 3 (2026-05): cATO toggle
    'cato'
  ));
