# Phase T1 Critical Fixes (2026-04-28)

Fixed 2 production-blocking bugs discovered through Phase T1 deep audit:

1. **vsp-scanner worker never started** — Worker binary existed but no systemd
   service. All scans stuck QUEUED for 16+ hours. Fixed by deploying
   vsp-scanner.service.

2. **Redis MISCONF stop-writes-on-bgsave-error** — Disk 97% full, RDB persist
   failed, all Redis writes blocked. Fixed by disabling bgsave error.

## First REAL scan
RID_VSPGO_RUN_20260428_053619_6cf6a886 detected:
- 38 CVEs (osv-scanner)  
- 11 network issues (nmap)
- 5 Go security issues (gosec, 1 HIGH)
- 2 SBOM components (syft)
Total: 56 real findings, 5 min duration
