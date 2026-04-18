# VSP Test Suite

3 levels of testing for VSP platform.

## Quick start

```bash
# Run all automated tests
make -f tests/Makefile.test full

# Individual suites
./tests/test_api.sh    # Smoke (30s)
./tests/test_data.sh   # Data quality (30s)
./tests/test_perf.sh   # Latency (30s)
```

## Level B — Manual test

See `CHECKLIST.md` for full manual walkthrough (~20 min).

Browser auto-probe:
1. Open http://127.0.0.1:8080, login
2. F12 → Console
3. Paste content of `browser_probe.js`
4. Wait ~60s for auto-click
5. Check report

## Level C — CI/CD integration

Add to `.github/workflows/test.yml`:

```yaml
- name: VSP Smoke Test
  run: ./tests/test_api.sh
  env:
    VSP_API: http://localhost:8080
```

## Environment variables

| Var | Default | Description |
|-----|---------|-------------|
| `VSP_API` | `http://127.0.0.1:8080` | Gateway URL |
| `VSP_USER` | `admin@vsp.local` | Login email |
| `VSP_PASS` | `admin` | Password |
| `VERBOSE` | `0` | Show passing tests too |
| `THRESHOLD_MS` | `2000` | Perf threshold (ms) |

## Exit codes

All scripts return:
- **0** — all checks pass
- **1** — one or more failed (safe for CI)

## Adding new tests

Edit `tests/test_api.sh` — add to `ENDPOINTS` array:
```bash
ENDPOINTS=(
  "new_endpoint|/api/v1/my/path|200"
)
```
