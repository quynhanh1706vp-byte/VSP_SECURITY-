// k6_slo.js — Service Level Objective smoke test.
//
// Validates that VSP's hot-path endpoints meet declared SLOs under
// realistic concurrent load. Fails the test run when any endpoint
// violates a threshold; CI should treat exit code != 0 as a release
// blocker.
//
// Targets (per docs/SLO.md):
//   • /api/v1/auth/check        : p95 < 100ms · err < 0.5%
//   • /api/v1/vsp/runs/index    : p95 < 400ms · err < 1%
//   • /api/v1/findings/summary  : p95 < 500ms · err < 1%
//   • /api/v1/audit/verify      : p95 < 800ms · err < 1%   (chain hash walk)
//   • /api/v1/dora              : p95 < 700ms · err < 1%   (multi-query agg)
//
// Run:
//   k6 run -e BASE_URL=https://staging.vsp.vn -e VSP_TOKEN=$TOK tests/load/k6_slo.js

import http from 'k6/http';
import { check, group } from 'k6';
import { Trend, Rate } from 'k6/metrics';

const BASE = __ENV.BASE_URL || 'http://localhost:8921';
const TOKEN = __ENV.VSP_TOKEN || '';

const headers = TOKEN
  ? { Authorization: `Bearer ${TOKEN}`, 'X-VSP-Locale': 'vi' }
  : { 'X-VSP-Locale': 'vi' };

const authCheckLat = new Trend('auth_check_p95', true);
const runsIndexLat = new Trend('runs_index_p95', true);
const findingsLat  = new Trend('findings_p95', true);
const auditLat     = new Trend('audit_verify_p95', true);
const doraLat      = new Trend('dora_p95', true);
const errs         = new Rate('errors');

export const options = {
  scenarios: {
    // Steady soak — what production sees on a busy day.
    soak: {
      executor: 'constant-vus',
      vus: 30,
      duration: '2m',
    },
  },
  thresholds: {
    'auth_check_p95':       ['p(95)<100'],
    'runs_index_p95':       ['p(95)<400'],
    'findings_p95':         ['p(95)<500'],
    'audit_verify_p95':     ['p(95)<800'],
    'dora_p95':             ['p(95)<700'],
    'errors':               ['rate<0.01'],   // < 1% errors across all calls
    'http_req_failed':      ['rate<0.01'],
  },
};

function timed(trend, resp) {
  trend.add(resp.timings.duration);
  errs.add(resp.status >= 400);
  check(resp, { 'status ok': r => r.status >= 200 && r.status < 400 });
}

export default function () {
  group('auth_check', () => {
    timed(authCheckLat, http.get(`${BASE}/api/v1/auth/check`, { headers }));
  });
  group('runs_index', () => {
    timed(runsIndexLat, http.get(`${BASE}/api/v1/vsp/runs/index?limit=20`, { headers }));
  });
  group('findings_summary', () => {
    timed(findingsLat, http.get(`${BASE}/api/v1/findings/summary`, { headers }));
  });
  group('audit_verify', () => {
    timed(auditLat, http.post(`${BASE}/api/v1/audit/verify`, null, { headers }));
  });
  group('dora_metrics', () => {
    timed(doraLat, http.get(`${BASE}/api/v1/dora?days=30`, { headers }));
  });
}
