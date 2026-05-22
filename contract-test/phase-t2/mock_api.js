// Expanded mock VSP API — tests the contract runner's auto-discovery + schema validation
const http = require('http');
const port = 18921;

const TS = new Date().toISOString();
const UUID = 'a1b2c3d4-5678-9abc-def0-123456789012';

const handlers = {
  // ── PUBLIC ──
  '/health': () => ({ status: 200, body: {
    status: 'ok', version: '2.0.0', timestamp: TS, uptime: '1h'
  }}),

  '/api/p4/health': () => ({ status: 200, body: {
    status: 'ok', version: '2.0.0', timestamp: TS
  }}),

  // ── AUTHED — VALID ──
  '/api/v1/vsp/runs': () => ({ status: 200, body: {
    total: 2, limit: 50, offset: 0,
    runs: [
      { id: UUID, mode: 'SAST', status: 'DONE', gate: 'PASS', score: 95.5, total_findings: 12, created_at: TS },
      { id: '11111111-1111-1111-1111-111111111111', mode: 'FULL', status: 'RUNNING' }
    ]
  }}),

  '/api/v1/vsp/runs/index': () => ({ status: 200, body: [
    { id: UUID, mode: 'IAC', status: 'DONE' }
  ]}),

  '/api/v1/vsp/findings': () => ({ status: 200, body: {
    total: 1,
    findings: [
      { id: UUID, run_id: UUID, severity: 'HIGH', tool: 'kics', rule_id: 'IAC-1' }
    ]
  }}),

  '/api/v1/vsp/findings/summary': () => ({ status: 200, body: {
    by_severity: { CRITICAL: 0, HIGH: 23, MEDIUM: 147 }
  }}),

  '/api/v1/vsp/gate/latest': () => ({ status: 200, body: {
    gate: 'WARN', score: 78.2, run_id: UUID
  }}),

  '/api/v1/vsp/sla_tracker': () => ({ status: 200, body: { breached: 2, ok: 145 }}),

  '/api/v1/correlation/incidents': () => ({ status: 200, body: [
    { id: 'INC-001', title: 'port scan from 1.2.3.4', severity: 'HIGH', status: 'open',
      rule_id: 'R-PORTSCAN', created_at: TS }
  ]}),

  '/api/v1/correlation/rules': () => ({ status: 200, body: [
    { id: 'R-PORTSCAN', name: 'Port scan detection', enabled: true, severity: 'HIGH' }
  ]}),

  '/api/v1/soar/playbooks': () => ({ status: 200, body: [
    { id: 'PB-1', name: 'Auto-isolate compromised host', enabled: true }
  ]}),

  '/api/v1/soar/runs': () => ({ status: 200, body: [
    { id: 'SR-1', playbook_id: 'PB-1', status: 'success', started_at: TS, completed_at: TS }
  ]}),

  '/api/v1/notifications': () => ({ status: 200, body: [
    { id: 'N1', type: 'scan', title: 'Scan complete', desc: 'FULL scan #42 passed', timestamp: TS, unread: true }
  ]}),

  // INTENTIONAL VIOLATION: wrong shape for metrics_slos (string instead of object)
  '/api/v1/vsp/metrics_slos': () => ({ status: 200, body: 'not even an object' }),
};

const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  const auth = req.headers['authorization'];
  const h = handlers[url];
  if (!h) {
    res.statusCode = 404;
    res.setHeader('Content-Type','application/json');
    res.end(JSON.stringify({error:'not found'}));
    return;
  }
  if (url !== '/health' && url !== '/api/p4/health' && !auth) {
    res.statusCode = 401;
    res.setHeader('Content-Type','application/json');
    res.end(JSON.stringify({error:'no token'}));
    return;
  }
  const r = h();
  res.statusCode = r.status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(r.body));
});

server.listen(port, () => {
  console.log('mock listening on ' + port);
});
