/**
 * VSP Platform — k6 Load Test
 * Cài k6: https://k6.io/docs/getting-started/installation/
 * Chạy: k6 run tests/load/k6_basic.js
 * Với options: k6 run --vus 10 --duration 30s tests/load/k6_basic.js
 */
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const loginErrors   = new Counter('login_errors');
const apiErrors     = new Counter('api_errors');
const cacheHitRate  = new Rate('cache_hit_rate');
const apiLatency    = new Trend('api_latency_ms', true);

// Config
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8921';
const EMAIL    = __ENV.VSP_EMAIL    || 'admin@vsp.local';
const PASSWORD = __ENV.VSP_PASSWORD || 'admin123';

// Load test options
export const options = {
  stages: [
    { duration: '30s', target: 10  },  // Ramp up
    { duration: '60s', target: 50  },  // Sustained load
    { duration: '30s', target: 100 },  // Spike
    { duration: '30s', target: 0   },  // Ramp down
  ],
  thresholds: {
    http_req_duration:  ['p(95)<500'],   // 95% requests < 500ms
    http_req_failed:    ['rate<0.01'],   // < 1% errors
    api_latency_ms:     ['p(99)<1000'],  // 99% < 1s
    cache_hit_rate:     ['rate>0.5'],    // > 50% cache hits
  },
};

// Setup: login một lần để lấy token
export function setup() {
  const res = http.post(`${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ email: EMAIL, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' } }
  );
  if (res.status !== 200) {
    console.error(`Login failed: ${res.status} ${res.body}`);
    return { token: '' };
  }
  const data = JSON.parse(res.body);
  console.log(`Setup: logged in as ${EMAIL}`);
  return { token: data.token };
}

// Main test
export default function(data) {
  const headers = {
    'Authorization': `Bearer ${data.token}`,
    'Content-Type': 'application/json',
  };

  // ── 1. Health check (no auth) ────────────────────────────────────────
  const health = http.get(`${BASE_URL}/health`);
  check(health, {
    'health: status 200': r => r.status === 200,
    'health: has checks': r => JSON.parse(r.body).checks !== undefined,
  });

  // ── 2. Hot endpoints (should hit cache) ──────────────────────────────
  const posture = http.get(`${BASE_URL}/api/v1/vsp/posture/latest`, { headers });
  const isHit = posture.headers['X-Cache'] === 'HIT';
  cacheHitRate.add(isHit);
  apiLatency.add(posture.timings.duration);
  check(posture, { 'posture: status 200': r => r.status === 200 });
  if (posture.status !== 200) apiErrors.add(1);

  // ── 3. Runs index (paginated, cached) ────────────────────────────────
  const runs = http.get(`${BASE_URL}/api/v1/vsp/runs/index?limit=20&offset=0`, { headers });
  apiLatency.add(runs.timings.duration);
  check(runs, { 'runs: status 200': r => r.status === 200 });

  // ── 4. Findings summary ──────────────────────────────────────────────
  const summary = http.get(`${BASE_URL}/api/v1/vsp/findings/summary`, { headers });
  check(summary, { 'findings: status 200': r => r.status === 200 });

  // ── 5. Auth refresh ──────────────────────────────────────────────────
  if (Math.random() < 0.1) { // 10% của requests
    const refresh = http.post(`${BASE_URL}/api/v1/auth/refresh`, null, { headers });
    check(refresh, { 'refresh: status 200': r => r.status === 200 });
  }

  sleep(1); // Think time
}

// Teardown: in summary
export function teardown(data) {
  console.log('Load test complete');
}
