# FEAT-08 — Network Flow Panel UX States (Sprint 5.4 — Phase A final)

## What
Fourth and final panel in Phase A using FEAT-04 shared VSPUXState module.
Closes Sprint 5 with 4/5 panels L2-ified (LogPipeline 5.5 deferred).

Strips 3 of 5 mock arrays (the "data" ones):
- CONNS (7 fake connections — including suspicious SSH from 185.220.101.47)
- PROTOS (6 fake protocol stats — HTTPS 42%, HTTP 18%, etc.)
- NDR_ALERTS (5 fake alerts — port scan, SSH brute force, etc.)

Keeps 2 mock arrays (graph topology template, dynamically updated):
- NODES (8 graph nodes with x/y coordinates: fw, web, app, db, k8s, ext1, ext2, gw)
- EDGES (8 graph edges between nodes)

## Why keep NODES + EDGES?
loadNetworkFlow() at line 220 already updates NODES with real IPs from
/api/v1/logs/hunt fallback. Topology layout is a canvas template:
positions (x/y) and visual styling are intentionally fixed.

The 3 stripped arrays were pure mock data that never updated from any backend
response — pure visual filler.

## Adds
- Skeleton state on entry (3 targets: #conn-tbody, #proto-list, #ndr-alerts)
- Empty state if TOKEN missing (3 targets)
- Population logic: tries to populate CONNS/PROTOS/NDR_ALERTS from backend
  response.connections / response.protocols / response.alerts if present
- Empty state per array if backend doesn't return that section
- Defensive: typeof VSPUXState !== 'undefined' guard via `hasUX` var

## Backend behavior (current)
- /api/v1/logs/network-flow may not return all 3 sections yet (schema TBD)
- Fallback: /api/v1/logs/hunt provides top-talkers + KPIs + suspicious node update
- 3 sub-tables show empty state with retry until backend extends the schema

## Apply
bash patches/feat/08-network-flow-uxstates/apply.sh

## Verify
Browser console at https://vsp.local:
  fetch('/panels/network_flow.html').then(r=>r.text()).then(t=>console.log({
    marker: t.includes('FEAT-08 PATCH APPLIED'),
    connsMockGone: !t.includes("src:'185.220.101.47',dst:'10.0.1.10'"),
    protosMockGone: !t.includes("name:'HTTPS',pct:42"),
    alertsMockGone: !t.includes('Port scan from 185.220.101.47'),
    emptyArrays: t.match(/var (CONNS|PROTOS|NDR_ALERTS)=\\[\\];/g)?.length || 0,
    nodesKept: t.includes("id:'fw'"),
    edgesKept: t.includes("from:'fw', to:'web'"),
    hasPopulation: t.includes('d.connections && d.connections.length')
  }))
Expected: marker true, all 3 mocks gone, emptyArrays=3, nodes/edges kept, population logic present.

Visual: open Network Flow panel ->
- Topology canvas: real graph (NODES/EDGES dynamically updated with real IPs)
- Connections table: skeleton -> "No connection history" (until backend extends)
- Protocol breakdown: skeleton -> "No protocol data" (until backend extends)
- NDR alerts: skeleton -> "No NDR alerts" (until backend extends)

## Rollback
bash patches/feat/08-network-flow-uxstates/rollback.sh

## Verified state (dry-run + apply)
- File: 1071 -> 1076 lines (+5 net: -17 mock, +22 logic)
- 5 patch steps reported success
- 3 empty arrays, 3 population checks, 1 typeof guard (consolidated via hasUX)
- NODES + EDGES preserved (graph topology template)

## Phase A status (after this commit)
| Sprint | Panel | Status |
|--------|-------|--------|
| 5.1 | Users | DONE (FEAT-05 / fc6ee08) |
| 5.2 | UEBA | DONE (FEAT-06 / c3e2ea4) |
| 5.3 | Threat Hunt | DONE (FEAT-07 / 0a251fc) |
| 5.4 | Network Flow | DONE (FEAT-08 / this commit) |
| 5.5 | Log Pipeline | DEFERRED (needs backend SSE endpoint) |
