-- 028_extend_feature_config.sql — extend the feature_config CHECK constraint
-- to allow the settings_* IDs and the REPORTS panel IDs added in later
-- passes. The Settings panel's per-tab Save buttons reuse this generic
-- table so we don't need one bespoke endpoint per section.

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
    'settings_retention'
  ));
