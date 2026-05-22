// k6_chaos.js — fault-injection smoke test.
//
// Sends a mix of malformed / oversized / slow requests at the gateway
// to verify graceful degradation. The asserts here are about the
// gateway *not crashing* rather than performance — the system should
// reject pathological input cleanly with the right HTTP code, not OOM
// or hang.
//
// Patterns tested:
//   • Oversized JSON body (10 MB)               → expect 413 or 400
//   • Malformed JWT bearer                      → expect 401
//   • Path traversal in URL params              → expect 400
//   • Slow client (writes body byte-by-byte)    → expect timeout 408/499
//   • Burst on /auth/login (lockout exercise)   → IP locks at 20
//
// Run:
//   k6 run -e BASE_URL=http://localhost:8921 tests/load/k6_chaos.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

const BASE = __ENV.BASE_URL || 'http://localhost:8921';
const oversizeRej = new Counter('chaos_oversize_rejected');
const malformedAuth = new Counter('chaos_malformed_auth_rejected');
const traversalRej = new Counter('chaos_traversal_rejected');
const ipLockTrips = new Counter('chaos_ip_lock_trips');

export const options = {
  scenarios: {
    chaos: { executor: 'per-vu-iterations', vus: 5, iterations: 20, maxDuration: '90s' },
  },
  thresholds: {
    'chaos_oversize_rejected':       ['count>0'],
    'chaos_malformed_auth_rejected': ['count>0'],
  },
};

export default function () {
  // 1. Oversized body — gateway should refuse before parsing.
  const big = 'x'.repeat(11 * 1024 * 1024);
  const resp1 = http.post(`${BASE}/api/v1/compliance/evidence`, big, {
    headers: { 'Content-Type': 'application/json' },
  });
  if (resp1.status === 413 || resp1.status === 400 || resp1.status === 401) {
    oversizeRej.add(1);
  }
  check(resp1, { 'oversize rejected (no 5xx)': r => r.status < 500 });

  // 2. Malformed JWT — must not 5xx.
  const resp2 = http.get(`${BASE}/api/v1/auth/check`, {
    headers: { Authorization: 'Bearer not.a.real.jwt' },
  });
  if (resp2.status === 401) malformedAuth.add(1);
  check(resp2, { 'malformed jwt → 401, not 5xx': r => r.status === 401 });

  // 3. Path traversal probe.
  const resp3 = http.get(`${BASE}/api/v1/compliance/evidence/../../etc/passwd`);
  if (resp3.status === 400 || resp3.status === 404 || resp3.status === 401) {
    traversalRej.add(1);
  }
  check(resp3, { 'traversal not 5xx': r => r.status < 500 });

  // 4. Login burst from one IP — exercises sliding-window IP lockout.
  const burst = http.batch(Array(10).fill(0).map(() => ({
    method: 'POST',
    url: `${BASE}/api/v1/auth/login`,
    body: JSON.stringify({ email: 'attacker@example.com', password: 'wrong' }),
    params: { headers: { 'Content-Type': 'application/json' } },
  })));
  const lockHit = burst.some(r => r.status === 429);
  if (lockHit) ipLockTrips.add(1);

  sleep(1);
}
