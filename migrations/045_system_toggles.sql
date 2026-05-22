-- 045_system_toggles.sql — extend feature_config CHECK to allow
-- per-tenant system-level toggles (SSE live stream, session timer,
-- session duration). Stored shape:
--
--   {
--     "sse_live_enabled":         true,
--     "session_timer_enabled":    true,
--     "session_timer_minutes":    30
--   }
--
-- Defaults (when row missing): all-on, 30-min session. Admin toggles
-- via the Settings panel; frontend reads at boot.

ALTER TABLE feature_config
  DROP CONSTRAINT IF EXISTS feature_config_feature_id_check;

ALTER TABLE feature_config
  ADD CONSTRAINT feature_config_feature_id_check
  CHECK (feature_id IN (
    -- 12 SIEM panels
    'ai_analyst', 'scheduler', 'correlation', 'soar',
    'log_ingestion', 'ueba', 'assets', 'sw_inventory',
    'network_flow', 'threat_hunt', 'vuln_mgmt', 'threat_intel',
    -- 7 REPORTS panels
    'analytics', 'executive', 'export',
    'users', 'cicd', 'integrations', 'settings',
    -- 7 Settings sub-tabs
    'settings_general', 'settings_scan', 'settings_alerts',
    'settings_apikeys', 'settings_security', 'settings_health',
    'settings_retention',
    -- Sprint 3
    'cato',
    -- Sprint 4
    'grafana',
    -- Sprint 12 (this migration)
    'system_toggles'
  ));
