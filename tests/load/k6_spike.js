/**
 * VSP Platform — k6 Spike Test
 * Test hệ thống chịu đựng sudden traffic spike
 * Chạy: k6 run tests/load/k6_spike.js
 */
import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8921';

export const options = {
  stages: [
    { duration: '10s', target: 5   },   // Normal
    { duration: '5s',  target: 200 },   // Spike!
    { duration: '10s', target: 200 },   // Sustained spike
    { duration: '5s',  target: 5   },   // Recovery
    { duration: '10s', target: 5   },   // Normal again
  ],
  thresholds: {
    http_req_failed:   ['rate<0.05'],   // < 5% errors during spike
    http_req_duration: ['p(95)<2000'],  // 95% < 2s during spike
  },
};

export function setup() {
  const res = http.post(`${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ email: 'admin@vsp.local', password: 'admin123' }),
    { headers: { 'Content-Type': 'application/json' } }
  );
  return { token: res.status === 200 ? JSON.parse(res.body).token : '' };
}

export default function(data) {
  const headers = { 'Authorization': `Bearer ${data.token}` };

  // Mostly read-heavy (realistic)
  const r = Math.random();
  if (r < 0.6) {
    http.get(`${BASE_URL}/api/v1/vsp/posture/latest`, { headers });
  } else if (r < 0.8) {
    http.get(`${BASE_URL}/api/v1/vsp/findings/summary`, { headers });
  } else if (r < 0.95) {
    http.get(`${BASE_URL}/health`);
  } else {
    http.post(`${BASE_URL}/api/v1/auth/refresh`, null, { headers });
  }

  sleep(0.5);
}
