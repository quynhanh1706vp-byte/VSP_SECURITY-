# Self-hosted GitHub Actions runner — VSP

## Why self-hosted

VSP opted for self-hosted runners over GitHub-hosted runners for three reasons:

1. **No commercial dependency.** GitHub Actions billing outages (ref SD-0049) block all CI. Self-hosted removes this single point of failure.
2. **Code sovereignty.** Scanning runs on infrastructure we control. Fits the VSP product philosophy of data-residency-aware security.
3. **Cost.** Free for unlimited minutes once the runner host exists.

## Prerequisites

- Linux machine (Ubuntu 22.04+ or Debian 12+ recommended) — always on, reachable from GitHub
- 4+ CPU, 8+ GB RAM, 40+ GB disk
- Docker installed (for containerized test deps: postgres, redis)
- Non-root user for the runner, with passwordless sudo for `apt install`

## Install the runner

From the dedicated CI host:

```bash
# As a non-root user (e.g., github-runner)
mkdir -p ~/actions-runner && cd ~/actions-runner

# Download — get the latest from
# https://github.com/actions/runner/releases
curl -o actions-runner-linux-x64.tar.gz -L \
  https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64-2.320.0.tar.gz
tar xzf actions-runner-linux-x64.tar.gz

# Get registration token from:
# https://github.com/quynhanh1706vp-byte/VSP_SECURITY-/settings/actions/runners/new
# (admin-only page; token rotates per use)

./config.sh \
  --url https://github.com/quynhanh1706vp-byte/VSP_SECURITY- \
  --token <TOKEN_FROM_GITHUB> \
  --name vsp-ci-01 \
  --labels self-hosted,linux,x64,vsp \
  --work _work \
  --unattended

# Install as systemd service so it restarts on reboot
sudo ./svc.sh install
sudo ./svc.sh start
sudo ./svc.sh status
```

## Update the workflow

Change `runs-on: ubuntu-latest` to `runs-on: [self-hosted, linux, x64]` in all jobs.

```yaml
jobs:
  lint:
    runs-on: [self-hosted, linux, x64]
```

For jobs that need Docker services (Postgres, Redis), ensure Docker is running on the runner host. The `services:` block in the workflow works the same as on GitHub-hosted runners.

## Security hardening

Self-hosted runners on a **public** repo are dangerous — anyone can submit a PR that runs code on your host. For VSP (private repo), this is acceptable but still tighten:

1. **Non-root user** — runner must not be root.
2. **Ephemeral runners** (optional) — re-register after each job; limits lateral movement. Use `--ephemeral` flag in `config.sh`.
3. **Firewall** — runner host only needs outbound HTTPS to `*.actions.githubusercontent.com`.
4. **Disk quota** — `_work/` grows unbounded otherwise.
5. **Don't install secrets locally** — all secrets come from GitHub via `${{ secrets.XXX }}` injection at job time.

## Runbook

| Situation | Action |
| --- | --- |
| Runner offline in GitHub UI | `ssh <host>; sudo systemctl status actions.runner.*` |
| Job hangs forever | Check disk: `df -h _work`; runner OOM: `dmesg \| tail` |
| Runner deleted in GitHub but service still running | `sudo ./svc.sh uninstall && ./config.sh remove --token <token>` |
| Update runner | `./svc.sh stop && ./config.sh remove && ...; reinstall` |

## Escape hatch

If self-hosted CI goes down and we need a quick GitHub-hosted fallback, the workflow can temporarily add a matrix:

```yaml
strategy:
  matrix:
    runner: [self-hosted, ubuntu-latest]
runs-on: ${{ matrix.runner }}
```

But don't leave this in — it doubles CI minutes and muddies pass/fail semantics.
