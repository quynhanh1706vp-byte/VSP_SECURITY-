-- 033_grafana_feature.sql — extend feature_config CHECK to allow the
-- grafana embed config. Stored shape:
--
--   {
--     "base_url": "https://grafana.internal/",
--     "default_theme": "dark",
--     "dashboards": [
--       {"uid": "vsp-overview", "title": "VSP Overview", "from": "now-24h"},
--       {"uid": "audit-chain",  "title": "Audit Chain Health"}
--     ]
--   }
--
-- The gateway never proxies Grafana traffic — embedding is iframe-direct,
-- so the operator must configure Grafana to allow iframe embedding from
-- the VSP origin (auth.iframe_allowed_origins or anonymous-org pattern).

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
    -- 7 Settings panel sub-tabs
    'settings_general', 'settings_scan', 'settings_alerts',
    'settings_apikeys', 'settings_security', 'settings_health',
    'settings_retention',
    -- Sprint 3
    'cato',
    -- Sprint 4
    'grafana'
  ));
