# Phase 7D — DAST (nuclei)

VSP Dynamic Application Security Testing microservice (port 8093).

Wraps `nuclei` CLI for production-grade DAST scans with async runner,
JSONL parser, and live progress polling.

## Components

| File | Lines | Purpose |
|---|---|---|
| `cmd/dast-api/main.go` | 600 | Microservice + nuclei runner |
| `frontend/vsp_dast_panel.js` | 580 | Full UI w/ live polling |
| `scripts/start-dast-api.sh` | 60 | Launcher |

**Total: ~1240 lines, stdlib only.**

## Profiles

| Profile | Templates | Severity | Timeout |
|---|---|---|---|
| `quick` | CVE only | critical, high | 2 min |
| `standard` | All | critical, high, medium | 8 min |
| `deep` | All | all | 30 min |

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | /healthz | Liveness + nuclei detection |
| GET | /tools/check | nuclei version + path |
| POST | /scan | `{target, profile}` → returns scan_id (async) |
| GET | /scans | List (without findings — fast) |
| GET | /scans/{id} | Full detail with findings |
| GET | /scans/{id}/findings | Findings only |
| POST | /scans/{id}/cancel | Cancel running |
| DELETE | /scans/{id} | Delete record |
| GET | /stats | KPIs |

## Install nuclei first

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
which nuclei  # → /home/test/go/bin/nuclei or similar
```

If `nuclei` not in PATH for the service, set `PATH` in the systemd unit
or restart your shell after `go install`.

## Install service

```bash
go build -o vsp-dast-api ./cmd/dast-api
./scripts/start-dast-api.sh
curl -s http://127.0.0.1:8093/healthz | jq
```

## Run a scan

```bash
# Submit
curl -s -XPOST http://127.0.0.1:8093/scan \
     -H 'content-type: application/json' \
     -d '{"target":"https://scanme.nmap.org","profile":"quick"}' | jq
# → {"id":"dast-...", "status":"queued"}

# Poll
SCAN_ID=...
curl -s http://127.0.0.1:8093/scans/$SCAN_ID | jq '{status, stats, findings: .findings[0:3]}'
```

## Wire frontend

```bash
cp frontend/vsp_dast_panel.js static/
sed -i '/vsp_email_panel\.js/a\    <script src="/vsp_dast_panel.js"></script>' static/index.html
```

## UI features

- **5 KPI cards**: Scans / Critical / High / Medium / Findings
- **+ New scan** modal with 3-card profile picker (visual selection)
- **Live progress**: scan list refreshes every 5s, detail modal polls every 2s
- **Animated progress bar** for running scans (CSS keyframe pulse)
- **Finding viewer**: severity pills, CVE badges, CVSS, references, tags
- **Drill-down**: click finding for full description + reference URLs

## Authorization warning

Built-in: scan modal shows ⚠ banner reminding user to only scan owned/permitted targets. This is **mandatory** for ethical use.
