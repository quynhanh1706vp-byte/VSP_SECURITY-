/* VSP — SIEM panel companion.

   Each panel under /panels/<id>.html loads inside an iframe of the main
   shell (index.html). Both are same-origin on :8921, so we reach back into
   the parent window to reuse the modal/form helpers from vsp_pro_realapi.js
   instead of duplicating ~500 LOC of UI primitives in every iframe.

   Drop one <script src="/vsp_siem_companion.js"></script> at the bottom of
   each /panels/<id>.html and the panel automatically gets:
     · ⚙ Configure  — opens a per-tenant settings modal whose form schema
                       is registered below by feature_id
     · 🔔 Notifications — opens the cross-panel notification config modal
     · Settings persist via PUT /api/v1/features/<id>/config (PRO-gated) */
(function(){
'use strict';
if (window.__VSP_SIEM_COMP__) return;
window.__VSP_SIEM_COMP__ = true;

// Reach the parent shell. If the panel is opened directly (debug), bail.
var PRO = (function(){
  try { return window.parent && window.parent !== window ? window.parent.VSP_PRO : null; }
  catch (_e) { return null; }
})();

/* ── Iframe fetch wrapper — CSRF + credentials only ─────────────────────
   Every panel under /panels/* runs in an iframe with its own window.fetch.
   Most panels already have an auth guard (vspAuthFetch in their <head>)
   that polls getToken() for up to 2.5s — that path correctly waits for
   the iframe-bootstrap postMessage handshake before calling the API.

   Earlier I tried injecting Authorization here too. That broke things
   because the gateway's auth middleware (internal/auth/middleware.go:95)
   returns 401 IMMEDIATELY on a malformed Bearer token without falling
   back to the vsp_token cookie. If parent.localStorage hadn't synced
   yet, my synchronous read returned empty/stale and the panel's polling
   wrapper never got to run.

   So: only inject CSRF + credentials. Auth is the panel's responsibility. */
(function installIframeFetchWrapper(){
  if (window.__VSP_IFRAME_FETCH_WRAP__) return;
  window.__VSP_IFRAME_FETCH_WRAP__ = true;
  var ORIG = window.fetch.bind(window);

  function readCSRF(){
    var m = document.cookie.match(/(?:^|;\s*)vsp_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : '';
  }

  // Defense-in-depth: scrub stub Authorization headers (e.g. `Bearer ` with
  // empty token) that some panel inline JS sets before the bootstrap
  // handshake finishes. The gateway's auth middleware returns 401 instantly
  // on a malformed Bearer without falling back to vsp_token cookie, so an
  // empty stub blocks the cookie path. The proper fix is to remove the
  // pre-set header in the panel HTML (done for ai_analyst.html), but this
  // guards future regressions across the 11 remaining panels.
  function isStubBearer(value){
    if (!value || typeof value !== 'string') return false;
    var v = value.trim();
    if (v === 'Bearer' || v === 'bearer') return true;
    if (/^Bearer\s/i.test(v)){
      var token = v.replace(/^Bearer\s+/i, '').trim();
      if (token.length < 20) return true;
    }
    return false;
  }

  window.fetch = function(input, init){
    try {
      var url = (typeof input === 'string') ? input : (input && input.url) || '';
      var sameOrigin = url.charAt(0) === '/' ||
                       url.indexOf(location.origin) === 0 ||
                       /^https?:\/\/127\.0\.0\.1:8921/.test(url);
      if (!sameOrigin) return ORIG(input, init);

      init = init || {};
      var method = (init.method || (input && input.method) || 'GET').toUpperCase();
      var headers = init.headers || {};
      if (headers instanceof Headers){
        var plain = {};
        headers.forEach(function(v, k){ plain[k] = v; });
        headers = plain;
      }

      // Strip stub Authorization headers (see isStubBearer comment).
      if (isStubBearer(headers.Authorization))   delete headers.Authorization;
      if (isStubBearer(headers.authorization))   delete headers.authorization;

      // CSRF — non-safe methods get the double-submit token.
      if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS'){
        var hasCSRF = !!(headers['X-CSRF-Token'] || headers['x-csrf-token']);
        if (!hasCSRF){
          var c = readCSRF();
          if (c) headers['X-CSRF-Token'] = c;
        }
      }

      init.headers = headers;
      if (!init.credentials) init.credentials = 'same-origin';
    } catch (_e) {}
    return ORIG(input, init);
  };
  (window.VSP_DEBUG && console.log('[VSP-SIEM-COMP] iframe fetch wrapper armed (CSRF + credentials only — auth handled by panel)'));
})();

if (!PRO || !PRO.api){
  // Silent: vsp_pro_panel_buttons.js (loaded by every iframe panel) provides
  // its own ⚙ Configure / 🔔 Notifications buttons that don't depend on
  // parent.VSP_PRO being ready. Logging this used to spam every iframe load
  // even though functionality was covered. Auth wrapper above still active.
  if (window.VSP_DEBUG) {
    (window.VSP_DEBUG && console.log('[VSP-SIEM-COMP] parent VSP_PRO not yet available (panel_buttons.js handles UI)'));
  }
  return;
}

/* ── Per-feature form schema ─────────────────────────────────────────────
   Keyed by the panel's filename (without .html). Each schema is a list of
   formModal({fields}) — see vsp_pro_realapi.js for the field types.
   Add an entry here as each panel goes through the upgrade pass; if the
   panel's URL isn't in the map, the companion stays silent. */
var SCHEMAS = {
  ai_analyst: {
    id: 'ai_analyst',
    title: 'AI Analyst — model + behaviour',
    sub: 'Tunes how the LLM-backed analyst answers compliance / triage questions for this tenant.',
    fields: [
      { id: 'model', label: 'LLM model', type: 'select', value: 'deepseek-coder-v2:16b', required: true,
        options: [
          { value: 'deepseek-coder-v2:16b', label: 'DeepSeek Coder v2 16B (local Ollama)' },
          { value: 'llama3.1:8b',           label: 'Llama 3.1 8B (local Ollama)' },
          { value: 'claude-sonnet-4-6',     label: 'Anthropic Claude Sonnet 4.6 (cloud)' },
          { value: 'gpt-4o-mini',           label: 'OpenAI GPT-4o-mini (cloud)' }
        ],
        hint: 'Cloud models need API keys configured at the platform level.' },
      { id: 'temperature', label: 'Temperature (0–2, lower = more deterministic)', type: 'number',
        value: 0.2, required: true, hint: 'Compliance answers should stay near 0.2; triage suggestions can go up to 0.7.' },
      { id: 'max_tokens', label: 'Max tokens per response', type: 'number',
        value: 2048, required: true, hint: '256–8192. Higher = longer answers, more cost / time.' },
      { id: 'cache_ttl_minutes', label: 'Response cache TTL (minutes)', type: 'number',
        value: 60, required: true, hint: '0 disables cache. Cached answers are tenant-scoped.' },
      { id: 'auto_suggest', label: 'Auto-suggest fixes inline with findings', type: 'checkbox',
        value: true },
      { id: 'show_citations', label: 'Show source citations under each answer', type: 'checkbox',
        value: true,
        hint: 'Helps audit trail; slightly increases response length.' },
      { id: 'redact_pii', label: 'Redact PII before sending to cloud models', type: 'checkbox',
        value: true,
        hint: 'When on, emails / IPs / SSNs are scrubbed before the prompt is forwarded.' }
    ],
    validate: function(v){
      if (v.temperature < 0 || v.temperature > 2) return 'Temperature 0–2';
      if (v.max_tokens < 256 || v.max_tokens > 8192) return 'Max tokens 256–8192';
      if (v.cache_ttl_minutes < 0 || v.cache_ttl_minutes > 1440) return 'Cache TTL 0–1440 min';
      return null;
    }
  },

  scheduler: {
    id: 'scheduler',
    title: 'Scheduler — job orchestration',
    sub: 'Cadence, concurrency and retention for periodic scans and ETL jobs scheduled via /api/sched.',
    fields: [
      { id: 'default_cron', label: 'Default scan cadence (cron)', type: 'text',
        value: '0 2 * * *', required: true,
        placeholder: '0 2 * * *',
        hint: '5-field cron. Default = daily at 02:00. Per-job overrides go in each schedule\'s edit form.' },
      { id: 'timezone', label: 'Default timezone', type: 'select',
        value: 'UTC', required: true,
        options: [
          { value: 'UTC',                label: 'UTC' },
          { value: 'America/New_York',   label: 'America/New_York (EST/EDT)' },
          { value: 'America/Los_Angeles',label: 'America/Los_Angeles (PST/PDT)' },
          { value: 'Europe/London',      label: 'Europe/London (GMT/BST)' },
          { value: 'Europe/Paris',       label: 'Europe/Paris (CET/CEST)' },
          { value: 'Asia/Ho_Chi_Minh',   label: 'Asia/Ho_Chi_Minh (ICT)' },
          { value: 'Asia/Tokyo',         label: 'Asia/Tokyo (JST)' }
        ] },
      { id: 'max_concurrent', label: 'Max concurrent jobs', type: 'number',
        value: 5, required: true,
        hint: '1–50. Hard cap on parallel job execution per tenant. Higher = faster catch-up after outage but more DB load.' },
      { id: 'retention_days', label: 'Run history retention (days)', type: 'number',
        value: 30, required: true,
        hint: '7–365. Older run rows are pruned by the scheduler\'s housekeeping loop.' },
      { id: 'notify_on_failure', label: 'Notify on failed run', type: 'checkbox',
        value: true,
        hint: 'Routes through the global Notifications config (Slack/Teams/PagerDuty).' },
      { id: 'retry_failed_runs', label: 'Auto-retry failed runs', type: 'checkbox',
        value: true,
        hint: 'Up to 3 retries with exponential backoff (1m, 5m, 15m).' },
      { id: 'pause_on_error_streak', label: 'Pause job after N consecutive failures', type: 'number',
        value: 5, required: true,
        hint: '1–100. Job moves to "paused" state after this many failures in a row to prevent runaway alerts.' }
    ],
    validate: function(v){
      // Very permissive cron sanity — scheduler-api validates the full grammar.
      if (!/^[\d\*\/,\-\s]+$/.test(v.default_cron)) return 'Cron must contain only digits, *, /, -, comma, space';
      if ((v.default_cron || '').split(/\s+/).filter(Boolean).length !== 5) return 'Cron must be 5 fields (min hour day mon dow)';
      if (v.max_concurrent < 1 || v.max_concurrent > 50) return 'Max concurrent 1–50';
      if (v.retention_days < 7 || v.retention_days > 365) return 'Retention 7–365 days';
      if (v.pause_on_error_streak < 1 || v.pause_on_error_streak > 100) return 'Pause threshold 1–100';
      return null;
    }
  },
  correlation: {
    id: 'correlation',
    title: 'Correlation engine — rule + incident behaviour',
    sub: 'Tunes how raw events fan into correlation rules and become incidents.',
    fields: [
      { id: 'window_minutes', label: 'Default correlation window (minutes)', type: 'number',
        value: 15, required: true, hint: '1–1440. Time window across which related events are grouped.' },
      { id: 'min_event_count', label: 'Minimum events to fire a rule', type: 'number',
        value: 3, required: true, hint: '1–1000. Below this threshold, events are stored but no incident is created.' },
      { id: 'auto_close_resolved_hours', label: 'Auto-close resolved incidents after (hours)', type: 'number',
        value: 72, required: true, hint: '1–8760 (1 year max). Resolved incidents older than this become read-only.' },
      { id: 'severity_floor', label: 'Severity floor (drop below this)', type: 'select',
        value: 'low', required: true,
        options: [
          { value: 'critical', label: 'CRITICAL only' },
          { value: 'high',     label: 'HIGH and above' },
          { value: 'medium',   label: 'MEDIUM and above' },
          { value: 'low',      label: 'LOW and above (default)' },
          { value: 'info',     label: 'All events (noisy)' }
        ] },
      { id: 'enable_ml_clustering', label: 'Enable ML clustering for similar events', type: 'checkbox',
        value: false, hint: 'Experimental. Uses a k-means model to group near-duplicates into one incident.' },
      { id: 'auto_assign_oncall', label: 'Auto-assign incidents to on-call', type: 'checkbox',
        value: true }
    ],
    validate: function(v){
      if (v.window_minutes < 1 || v.window_minutes > 1440) return 'Window 1–1440 min';
      if (v.min_event_count < 1 || v.min_event_count > 1000) return 'Min event count 1–1000';
      if (v.auto_close_resolved_hours < 1 || v.auto_close_resolved_hours > 8760) return 'Auto-close 1–8760 h';
      return null;
    }
  },

  soar: {
    id: 'soar',
    title: 'SOAR — playbook execution policy',
    sub: 'Sandbox limits, approval requirements and timeout for the SOAR engine.',
    fields: [
      { id: 'max_concurrent_runs', label: 'Max concurrent playbook runs', type: 'number',
        value: 100, required: true, hint: '1–500. Hard cap on parallel SOAR runs per tenant.' },
      { id: 'default_timeout_seconds', label: 'Default playbook timeout (seconds)', type: 'number',
        value: 300, required: true, hint: '30–3600. Playbooks exceeding this are killed.' },
      { id: 'require_approval_for_destructive', label: 'Require approval for destructive actions', type: 'checkbox',
        value: true, hint: 'Delete / revoke / kill steps go through the human approval queue first.' },
      { id: 'max_steps_per_playbook', label: 'Max steps per playbook', type: 'number',
        value: 50, required: true, hint: '1–500. Prevents runaway recursion in poorly-designed playbooks.' },
      { id: 'enable_dry_run_mode', label: 'Enable dry-run mode by default', type: 'checkbox',
        value: false, hint: 'When on, every "execute" call defaults to simulate mode. Override with explicit ?live=true.' },
      { id: 'audit_retention_days', label: 'Run audit retention (days)', type: 'number',
        value: 365, required: true, hint: '30–2555. SOC2 baseline is 365.' }
    ],
    validate: function(v){
      if (v.max_concurrent_runs < 1 || v.max_concurrent_runs > 500) return 'Max concurrent 1–500';
      if (v.default_timeout_seconds < 30 || v.default_timeout_seconds > 3600) return 'Timeout 30–3600 s';
      if (v.max_steps_per_playbook < 1 || v.max_steps_per_playbook > 500) return 'Max steps 1–500';
      if (v.audit_retention_days < 30 || v.audit_retention_days > 2555) return 'Retention 30–2555 d';
      return null;
    }
  },

  log_pipeline: {
    id: 'log_ingestion',
    title: 'Log ingestion — pipeline + retention',
    sub: 'Throughput, parser policy and storage retention for the SIEM log pipeline.',
    fields: [
      { id: 'max_eps', label: 'Max events / second (rate limit)', type: 'number',
        value: 10000, required: true, hint: '100–500000. Excess events are dropped after this cap to protect downstream.' },
      { id: 'parser_strict_mode', label: 'Strict parser mode (drop unparseable lines)', type: 'checkbox',
        value: false, hint: 'When off, unparseable lines are stored with type=raw for forensic backfill.' },
      { id: 'hot_retention_days', label: 'Hot tier retention (days)', type: 'number',
        value: 30, required: true, hint: '1–365. Indexed, fast-search storage.' },
      { id: 'cold_retention_days', label: 'Cold tier retention (days)', type: 'number',
        value: 365, required: true, hint: '30–2555. Compressed object storage. Search is slower.' },
      { id: 'enable_geoip', label: 'Enrich with GeoIP', type: 'checkbox',
        value: true, hint: 'Adds source_country / city to network log events. Uses the platform GeoIP database.' },
      { id: 'enable_user_agent_parse', label: 'Parse User-Agent strings', type: 'checkbox',
        value: true }
    ],
    validate: function(v){
      if (v.max_eps < 100 || v.max_eps > 500000) return 'Max EPS 100–500000';
      if (v.hot_retention_days < 1 || v.hot_retention_days > 365) return 'Hot retention 1–365 d';
      if (v.cold_retention_days < 30 || v.cold_retention_days > 2555) return 'Cold retention 30–2555 d';
      if (v.cold_retention_days < v.hot_retention_days) return 'Cold retention must be ≥ hot retention';
      return null;
    }
  },

  ueba: {
    id: 'ueba',
    title: 'UEBA — behavioural baselines + anomaly thresholds',
    sub: 'Tunes when a user / entity diverges enough from its learned baseline to fire an anomaly.',
    fields: [
      { id: 'baseline_window_days', label: 'Baseline learning window (days)', type: 'number',
        value: 14, required: true, hint: '7–90. Longer = more stable baseline but slower reaction to permanent changes.' },
      { id: 'anomaly_zscore_threshold', label: 'Anomaly Z-score threshold', type: 'number',
        value: 3, required: true, hint: '1.0–10.0. Higher = fewer anomalies (more precise, less recall). 3 ≈ p99.7.' },
      { id: 'login_geo_velocity_kmh', label: 'Impossible-travel velocity (km/h)', type: 'number',
        value: 1000, required: true, hint: '500–10000. Two logins from different geos faster than this fire an anomaly.' },
      { id: 'after_hours_window', label: 'After-hours definition (e.g. "22:00-06:00")', type: 'text',
        value: '22:00-06:00', required: true,
        hint: '24-hour clock. Logins in this window are flagged for managers to review.' },
      { id: 'enable_peer_group_analysis', label: 'Enable peer-group analysis', type: 'checkbox',
        value: true, hint: 'Compares each user to others with the same role/department.' },
      { id: 'auto_lock_on_critical', label: 'Auto-lock account on CRITICAL anomaly', type: 'checkbox',
        value: false, hint: 'Aggressive: high false-positive impact. Off by default.' }
    ],
    validate: function(v){
      if (v.baseline_window_days < 7 || v.baseline_window_days > 90) return 'Baseline 7–90 d';
      if (v.anomaly_zscore_threshold < 1 || v.anomaly_zscore_threshold > 10) return 'Z-score 1–10';
      if (v.login_geo_velocity_kmh < 500 || v.login_geo_velocity_kmh > 10000) return 'Velocity 500–10000 km/h';
      if (!/^\d{2}:\d{2}-\d{2}:\d{2}$/.test(v.after_hours_window)) return 'Window format: HH:MM-HH:MM';
      return null;
    }
  },

  assets: {
    id: 'assets',
    title: 'Asset inventory — discovery + risk scoring',
    sub: 'How the platform discovers assets and computes their criticality score.',
    fields: [
      { id: 'auto_discovery_enabled', label: 'Auto-discover assets from log sources', type: 'checkbox',
        value: true, hint: 'Adds new hostnames seen in incoming logs to the inventory automatically.' },
      { id: 'criticality_default', label: 'Default criticality for new assets', type: 'select',
        value: 'medium', required: true,
        options: [
          { value: 'critical', label: 'CRITICAL (production, customer-facing)' },
          { value: 'high',     label: 'HIGH (infra, dev)' },
          { value: 'medium',   label: 'MEDIUM (default)' },
          { value: 'low',      label: 'LOW (test, sandbox)' }
        ] },
      { id: 'stale_threshold_days', label: 'Stale asset threshold (days)', type: 'number',
        value: 30, required: true, hint: '7–365. Assets with no logs/heartbeats for this long are marked stale.' },
      { id: 'auto_archive_stale', label: 'Auto-archive stale assets after threshold', type: 'checkbox',
        value: false, hint: 'Stale assets are still queryable but excluded from active dashboards.' },
      { id: 'tag_naming_convention', label: 'Tag naming convention', type: 'select',
        value: 'kebab-case', required: true,
        options: [
          { value: 'kebab-case', label: 'kebab-case (env-prod)' },
          { value: 'snake_case', label: 'snake_case (env_prod)' },
          { value: 'free-form',  label: 'Free-form (no validation)' }
        ] }
    ],
    validate: function(v){
      if (v.stale_threshold_days < 7 || v.stale_threshold_days > 365) return 'Stale threshold 7–365 d';
      return null;
    }
  },

  sw_inventory: {
    id: 'sw_inventory',
    title: 'Software inventory — scan + license policy',
    sub: 'How the SW agent collects installed packages and what license stances trigger findings.',
    fields: [
      { id: 'scan_interval_hours', label: 'Agent scan interval (hours)', type: 'number',
        value: 24, required: true, hint: '1–168. Lower = more current inventory but more agent CPU.' },
      { id: 'cve_match_severity_floor', label: 'Report CVEs at severity ≥', type: 'select',
        value: 'high', required: true,
        options: [
          { value: 'critical', label: 'CRITICAL only' },
          { value: 'high',     label: 'HIGH and above (default)' },
          { value: 'medium',   label: 'MEDIUM and above' },
          { value: 'low',      label: 'LOW and above' }
        ] },
      { id: 'license_policy', label: 'License policy', type: 'select',
        value: 'sbom-track', required: true,
        options: [
          { value: 'sbom-track',  label: 'Track in SBOM (no enforcement)' },
          { value: 'warn-copyleft',label: 'Warn on copyleft (GPL/AGPL/LGPL)' },
          { value: 'block-agpl',  label: 'Block AGPL outright' }
        ] },
      { id: 'block_eol_software', label: 'Flag end-of-life software as critical', type: 'checkbox',
        value: true, hint: 'Packages past upstream EOL date are auto-flagged regardless of CVE count.' },
      { id: 'whitelist_packages', label: 'Whitelist (comma-separated package names)', type: 'textarea',
        value: '',
        placeholder: 'apt-utils, ca-certificates',
        hint: 'These packages are excluded from EOL/license findings. One name per package, comma-separated.' }
    ],
    validate: function(v){
      if (v.scan_interval_hours < 1 || v.scan_interval_hours > 168) return 'Scan interval 1–168 h';
      if ((v.whitelist_packages || '').length > 4000) return 'Whitelist too long (max 4000 chars)';
      return null;
    }
  },

  network_flow: {
    id: 'network_flow',
    title: 'Network flow — capture + alert thresholds',
    sub: 'BPF filter, capture limits and DNS / proxy enrichment for the network sensor.',
    fields: [
      { id: 'bpf_filter', label: 'BPF capture filter', type: 'text',
        value: 'tcp or udp or icmp', required: true,
        hint: 'tcpdump-syntax. Use this to exclude voice/storage traffic. Default = all stateful protocols.' },
      { id: 'max_pps', label: 'Max packets / second (rate limit)', type: 'number',
        value: 100000, required: true, hint: '1000–5000000. Drops above this protect the sensor host.' },
      { id: 'capture_payload_bytes', label: 'Per-packet payload capture (bytes)', type: 'number',
        value: 96, required: true, hint: '0–1500. 0 = headers only. 96 covers most HTTP method+URL lines.' },
      { id: 'enable_dns_enrichment', label: 'Enable DNS reverse-lookup enrichment', type: 'checkbox',
        value: true },
      { id: 'enable_proxy_decoding', label: 'Decode proxy / load-balancer headers (X-Forwarded-For)', type: 'checkbox',
        value: true },
      { id: 'alert_on_egress_to_block', label: 'Alert on egress to a blocked geo / ASN', type: 'checkbox',
        value: true, hint: 'Uses the threat-intel feed list of sanctioned countries / known malicious ASNs.' }
    ],
    validate: function(v){
      if (v.max_pps < 1000 || v.max_pps > 5000000) return 'Max PPS 1000–5000000';
      if (v.capture_payload_bytes < 0 || v.capture_payload_bytes > 1500) return 'Payload bytes 0–1500';
      if ((v.bpf_filter || '').length > 1000) return 'BPF filter too long';
      return null;
    }
  },

  threat_hunt: {
    id: 'threat_hunt',
    title: 'Threat Hunt — saved queries + scheduling',
    sub: 'Persisted hunt queries that run on a cadence and surface results into the SIEM workflow.',
    fields: [
      { id: 'default_lookback_hours', label: 'Default lookback window (hours)', type: 'number',
        value: 24, required: true, hint: '1–720. How far back saved hunt queries scan by default.' },
      { id: 'query_timeout_seconds', label: 'Per-query timeout (seconds)', type: 'number',
        value: 60, required: true, hint: '5–600. Long queries are killed to protect the warehouse.' },
      { id: 'auto_create_incidents', label: 'Auto-create incident when hunt finds matches', type: 'checkbox',
        value: false, hint: 'Aggressive: only enable when your hunt queries have very low false-positive rates.' },
      { id: 'min_match_severity', label: 'Minimum severity to surface', type: 'select',
        value: 'medium', required: true,
        options: [
          { value: 'critical', label: 'CRITICAL only' },
          { value: 'high',     label: 'HIGH and above' },
          { value: 'medium',   label: 'MEDIUM and above (default)' },
          { value: 'low',      label: 'LOW and above (noisy)' }
        ] },
      { id: 'enable_mitre_mapping', label: 'Auto-map matches to MITRE ATT&CK techniques', type: 'checkbox',
        value: true, hint: 'Uses the platform MITRE knowledge base + simple rule-based tagger.' }
    ],
    validate: function(v){
      if (v.default_lookback_hours < 1 || v.default_lookback_hours > 720) return 'Lookback 1–720 h';
      if (v.query_timeout_seconds < 5 || v.query_timeout_seconds > 600) return 'Timeout 5–600 s';
      return null;
    }
  },

  vuln_mgmt: {
    id: 'vuln_mgmt',
    title: 'Vulnerability management — SLA + auto-triage',
    sub: 'Per-severity remediation SLAs and how new findings are routed.',
    fields: [
      { id: 'sla_critical_hours', label: 'CRITICAL remediation SLA (hours)', type: 'number',
        value: 24, required: true, hint: '1–168. PCI-DSS baseline = 24 h.' },
      { id: 'sla_high_hours', label: 'HIGH remediation SLA (hours)', type: 'number',
        value: 168, required: true, hint: '24–720. Default = 7 days.' },
      { id: 'sla_medium_hours', label: 'MEDIUM remediation SLA (hours)', type: 'number',
        value: 720, required: true, hint: '168–2160. Default = 30 days.' },
      { id: 'auto_assign_to_owner', label: 'Auto-assign findings to asset owner', type: 'checkbox',
        value: true, hint: 'Looks up owner via Asset Inventory tags.' },
      { id: 'enable_kev_priority', label: 'Boost CISA KEV catalog findings to CRITICAL', type: 'checkbox',
        value: true, hint: 'CVEs in the Known-Exploited-Vulnerabilities feed get CRITICAL severity automatically.' },
      { id: 'auto_close_fixed_after_days', label: 'Auto-close fixed findings after (days)', type: 'number',
        value: 7, required: true, hint: '1–90. After this many consecutive scans without the finding, status → resolved.' }
    ],
    validate: function(v){
      if (v.sla_critical_hours < 1 || v.sla_critical_hours > 168) return 'CRIT SLA 1–168 h';
      if (v.sla_high_hours < 24 || v.sla_high_hours > 720) return 'HIGH SLA 24–720 h';
      if (v.sla_medium_hours < 168 || v.sla_medium_hours > 2160) return 'MEDIUM SLA 168–2160 h';
      if (v.sla_high_hours <= v.sla_critical_hours) return 'HIGH SLA must be greater than CRIT';
      if (v.sla_medium_hours <= v.sla_high_hours) return 'MEDIUM SLA must be greater than HIGH';
      if (v.auto_close_fixed_after_days < 1 || v.auto_close_fixed_after_days > 90) return 'Auto-close 1–90 d';
      return null;
    }
  },

  users: {
    id: 'users',
    title: 'Users — RBAC + session policy',
    sub: 'How user roles are mapped, session timeouts, and audit retention.',
    fields: [
      { id: 'default_role', label: 'Default role for new users', type: 'select',
        value: 'analyst', required: true,
        options: [
          { value: 'admin',   label: 'admin (full access)' },
          { value: 'analyst', label: 'analyst (view + triage)' },
          { value: 'dev',     label: 'dev (CI / API tokens)' },
          { value: 'auditor', label: 'auditor (read-only)' }
        ] },
      { id: 'session_idle_timeout_min', label: 'Idle session timeout (minutes)', type: 'number',
        value: 30, required: true, hint: '5–480. Forces re-auth after this much inactivity.' },
      { id: 'session_absolute_max_hours', label: 'Absolute session max age (hours)', type: 'number',
        value: 8, required: true, hint: '1–168. Hard cap regardless of activity.' },
      { id: 'require_mfa_for_admins', label: 'Require MFA for admin role', type: 'checkbox',
        value: true, hint: 'Auditor + dev roles can opt in via /auth/mfa.' },
      { id: 'audit_retention_days', label: 'User-action audit retention (days)', type: 'number',
        value: 365, required: true, hint: '30–2555. SOC2 baseline = 365.' },
      { id: 'allowed_email_domains', label: 'Allowed email domains (comma-separated)', type: 'text',
        value: '', placeholder: 'acme.com, contractor.acme.com',
        hint: 'Optional. New users must register with one of these domains. Blank = any.' }
    ],
    validate: function(v){
      if (v.session_idle_timeout_min < 5 || v.session_idle_timeout_min > 480) return 'Idle 5–480 min';
      if (v.session_absolute_max_hours < 1 || v.session_absolute_max_hours > 168) return 'Max session 1–168 h';
      if (v.audit_retention_days < 30 || v.audit_retention_days > 2555) return 'Audit retention 30–2555 d';
      return null;
    }
  },

  cicd: {
    id: 'cicd',
    title: 'CI/CD — gate policy + auto-fix',
    sub: 'Pipeline gating thresholds and how PR-bot interacts with CI.',
    fields: [
      { id: 'gate_severity_floor', label: 'Block PR if any finding at severity ≥', type: 'select',
        value: 'critical', required: true,
        options: [
          { value: 'critical', label: 'CRITICAL only (default)' },
          { value: 'high',     label: 'HIGH and above (strict)' },
          { value: 'medium',   label: 'MEDIUM and above (very strict)' }
        ] },
      { id: 'max_findings_per_pr', label: 'Max new findings per PR', type: 'number',
        value: 50, required: true, hint: '1–500. PRs introducing more new findings are auto-blocked.' },
      { id: 'enable_auto_fix_pr', label: 'Bot opens auto-fix PRs', type: 'checkbox',
        value: true, hint: 'When off, bot only suggests fixes inline; no PR is created.' },
      { id: 'require_review_before_merge', label: 'Require human review before merge', type: 'checkbox',
        value: true, hint: 'Even if all checks pass, require ≥1 human approval.' },
      { id: 'enable_signed_commits', label: 'Require signed commits (cosign / GPG)', type: 'checkbox',
        value: false },
      { id: 'block_merge_on_secret_leak', label: 'Block merge if gitleaks finds new secrets', type: 'checkbox',
        value: true, hint: 'Even one new credential leak prevents the merge regardless of severity floor.' }
    ],
    validate: function(v){
      if (v.max_findings_per_pr < 1 || v.max_findings_per_pr > 500) return 'Max findings 1–500';
      return null;
    }
  },

  integrations: {
    id: 'integrations',
    title: 'Integrations — connectors + OAuth scope',
    sub: 'Third-party connectors (Jira / ServiceNow / GitHub) and their default scopes.',
    fields: [
      { id: 'jira_default_project', label: 'Default Jira project key', type: 'text',
        value: '', placeholder: 'SEC',
        hint: 'Findings auto-create tickets here. Per-finding override via the Triage panel.' },
      { id: 'jira_issue_type', label: 'Default Jira issue type', type: 'select',
        value: 'Task',
        options: [
          { value: 'Bug',   label: 'Bug' },
          { value: 'Task',  label: 'Task' },
          { value: 'Story', label: 'Story' }
        ] },
      { id: 'servicenow_instance', label: 'ServiceNow instance URL', type: 'text',
        value: '', placeholder: 'https://acme.service-now.com',
        hint: 'OAuth credentials configured at the platform level.' },
      { id: 'github_default_repo', label: 'Default GitHub repo for auto-PR', type: 'text',
        value: '', placeholder: 'org/repo',
        hint: 'PR-bot opens fix PRs here unless the finding has a repo binding.' },
      { id: 'enable_2way_sync', label: 'Two-way sync (status updates flow back to VSP)', type: 'checkbox',
        value: false, hint: 'When on, ticket close in Jira/SN auto-resolves the VSP finding.' },
      { id: 'webhook_signing_required', label: 'Require HMAC-SHA256 signing on inbound webhooks', type: 'checkbox',
        value: true }
    ],
    validate: function(v){
      if (v.jira_default_project && !/^[A-Z][A-Z0-9_]{1,9}$/.test(v.jira_default_project))
        return 'Jira project key: 2–10 uppercase chars, digits + underscore';
      if (v.servicenow_instance && !/^https:\/\//.test(v.servicenow_instance))
        return 'ServiceNow URL must start with https://';
      return null;
    }
  },

  settings: {
    id: 'settings',
    title: 'Settings — feature flags + UI preferences',
    sub: 'Tenant-wide feature toggles (AI triage, threat feeds, dashboard defaults).',
    fields: [
      { id: 'enable_ai_triage', label: 'AI triage on every finding', type: 'checkbox',
        value: true, hint: 'Sends finding context to AI Analyst for severity refinement + remediation hint.' },
      { id: 'enable_vn_threat_feeds', label: 'Enable Vietnamese threat feeds', type: 'checkbox',
        value: false, hint: 'VNCERT + ThreatBook regional intel. Adds ~5min/sync to feed pull.' },
      { id: 'default_dashboard', label: 'Default landing dashboard', type: 'select',
        value: 'overview', required: true,
        options: [
          { value: 'overview',  label: 'Security overview' },
          { value: 'siem',      label: 'SIEM live' },
          { value: 'compliance',label: 'Compliance' },
          { value: 'pro',       label: 'Cloud-native PRO' }
        ] },
      { id: 'theme_preference', label: 'Default theme', type: 'select',
        value: 'dark', required: true,
        options: [
          { value: 'dark',  label: 'Dark (recommended for SOC)' },
          { value: 'light', label: 'Light' },
          { value: 'auto',  label: 'Match system' }
        ] },
      { id: 'show_classification_banner', label: 'Show classification banner (UNCLASSIFIED // FOUO)', type: 'checkbox',
        value: true, hint: 'Required for FedRAMP/CMMC compliance contexts.' },
      { id: 'enable_telemetry', label: 'Send usage telemetry to vendor', type: 'checkbox',
        value: false, hint: 'Off by default. Telemetry helps prioritise platform improvements.' }
    ]
  },

  threat_intel: {
    id: 'threat_intel',
    title: 'Threat intel — feeds + enrichment',
    sub: 'Which IOC feeds to ingest and how aggressively to enrich findings.',
    fields: [
      { id: 'feed_misp_enabled', label: 'MISP feed', type: 'checkbox',
        value: true, hint: 'Open-source MISP shared instance.' },
      { id: 'feed_otx_enabled', label: 'AlienVault OTX feed', type: 'checkbox',
        value: true },
      { id: 'feed_abuseipdb_enabled', label: 'AbuseIPDB feed', type: 'checkbox',
        value: false, hint: 'Requires API key in /etc/vsp/env.production.' },
      { id: 'feed_crowdstrike_enabled', label: 'CrowdStrike Falcon Intel', type: 'checkbox',
        value: false, hint: 'Commercial feed. Requires API credentials.' },
      { id: 'enrichment_timeout_seconds', label: 'Per-IOC enrichment timeout (seconds)', type: 'number',
        value: 5, required: true, hint: '1–60. If feed is slow we time out and continue without that source.' },
      { id: 'cache_ttl_hours', label: 'IOC enrichment cache TTL (hours)', type: 'number',
        value: 24, required: true, hint: '1–168. IOC reputations rarely change within a day.' },
      { id: 'auto_block_known_bad', label: 'Auto-block traffic from known-malicious IPs', type: 'checkbox',
        value: false, hint: 'Pushes IOCs into the network-flow blocklist. Aggressive: review false-positive risk.' }
    ],
    validate: function(v){
      if (v.enrichment_timeout_seconds < 1 || v.enrichment_timeout_seconds > 60) return 'Enrichment timeout 1–60 s';
      if (v.cache_ttl_hours < 1 || v.cache_ttl_hours > 168) return 'Cache TTL 1–168 h';
      return null;
    }
  }
};

function detectFeatureID(){
  var p = (location.pathname || '').replace(/^\/panels\//, '').replace(/\.html$/, '');
  return p in SCHEMAS ? p : null;
}

function injectButtons(featureID){
  // Guard against double-inject on hot reload.
  if (document.getElementById('vsp-siem-companion-bar')) return;
  var bar = document.createElement('div');
  bar.id = 'vsp-siem-companion-bar';
  bar.style.cssText = [
    'position:fixed', 'top:10px', 'right:14px', 'z-index:9000',
    'display:flex', 'gap:6px', 'padding:6px',
    'background:rgba(13,20,36,.85)', 'backdrop-filter:blur(4px)',
    'border:1px solid rgba(255,255,255,.08)', 'border-radius:6px'
  ].join(';');
  bar.innerHTML =
    '<button class="vsp-siem-btn" data-act="cfg" title="Configure tenant settings">⚙ Configure</button>' +
    '<button class="vsp-siem-btn" data-act="notif" title="Notification channels">🔔 Notifications</button>';
  document.body.appendChild(bar);

  // Local CSS (the iframe doesn't load the main app's CSS).
  // The bar sits at z-index 9000 which is above most panel-local modals
  // (scheduler's .modal-overlay has z-index:200), so the user saw the
  // ⚙ Configure / 🔔 Notifications buttons floating over the modal's
  // close X. :has() lets us auto-hide the bar whenever any
  // .modal-overlay.open exists in the same iframe — no JS observer
  // needed, no per-panel coordination.
  if (!document.getElementById('vsp-siem-comp-css')){
    var s = document.createElement('style');
    s.id = 'vsp-siem-comp-css';
    s.textContent =
      '.vsp-siem-btn{background:#0f172a;color:#cbd5e1;border:1px solid rgba(34,211,238,.25);' +
      '  border-radius:4px;padding:6px 11px;font-size:11px;cursor:pointer;' +
      '  font-family:system-ui,sans-serif;transition:background .12s,color .12s}' +
      '.vsp-siem-btn:hover{background:rgba(34,211,238,.12);color:#22d3ee}' +
      '.vsp-siem-btn[data-act="cfg"]{border-color:rgba(34,211,238,.45);color:#22d3ee}' +
      'body:has(.modal-overlay.open) #vsp-siem-companion-bar,' +
      'body:has(.vspm-overlay) #vsp-siem-companion-bar,' +
      'body:has(#pro-overlay.open) #vsp-siem-companion-bar{display:none!important}';
    document.head.appendChild(s);
  }

  bar.addEventListener('click', function(e){
    var btn = e.target.closest('button[data-act]');
    if (!btn) return;
    if (btn.dataset.act === 'cfg')   openConfigure(featureID);
    if (btn.dataset.act === 'notif') PRO.openNotifications();
  });
}

function openConfigure(featureID){
  var schema = SCHEMAS[featureID];
  if (!schema) return;
  PRO.api.fetch('/api/v1/features/' + featureID + '/config').then(function(resp){
    var saved = (resp && resp.config) || {};
    // Merge saved values into the schema's default values.
    var fields = schema.fields.map(function(f){
      var copy = Object.assign({}, f);
      if (saved[f.id] !== undefined) copy.value = saved[f.id];
      return copy;
    });

    // Use parent's formModal so the modal lives in the parent DOM and the
    // backdrop can cover the whole shell (including this iframe).
    var formModal = window.parent.VSP_PRO_FORM_MODAL;
    if (!formModal){
      // formModal is defined inside vsp_pro_realapi.js IIFE — we exposed
      // openNotifications + api.fetch but not formModal. Fall back to a
      // window.parent.alert path that just edits via PUT.
      var raw = window.prompt('Edit JSON for ' + featureID + ' config:', JSON.stringify(saved, null, 2));
      if (!raw) return;
      var parsed; try { parsed = JSON.parse(raw); } catch (_e){ alert('Invalid JSON'); return; }
      PRO.api.fetch('/api/v1/features/' + featureID + '/config', {
        method: 'PUT', body: JSON.stringify({ config: parsed })
      }).then(function(){ alert('Saved'); }).catch(function(e){ alert('Save failed: ' + (e.error || e.message || e)); });
      return;
    }
    formModal({
      title: schema.title, sub: schema.sub,
      submitLabel: 'Save', wide: true,
      fields: fields,
      validate: schema.validate,
      commit: function(values){
        return PRO.api.fetch('/api/v1/features/' + featureID + '/config', {
          method: 'PUT', body: JSON.stringify({ config: values })
        });
      }
    }).then(function(v){
      if (v && window.parent.toast) window.parent.toast(featureID + ' settings saved','success');
    });
  }).catch(function(err){
    if (err && err.is402){
      alert('This feature requires a PRO plan. Contact sales to upgrade.');
      return;
    }
    alert('Config fetch failed: ' + (err.error || err.message || err));
  });
}

var fid = detectFeatureID();
if (fid){
  if (document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', function(){ injectButtons(fid); });
  } else {
    injectButtons(fid);
  }
  (window.VSP_DEBUG && console.log('[VSP-SIEM-COMP] active for feature:', fid));
} else {
  (window.VSP_DEBUG && console.log('[VSP-SIEM-COMP] no schema registered for', location.pathname));
}
})();
