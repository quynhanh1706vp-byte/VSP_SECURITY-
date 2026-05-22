# FEAT-16 — ConMon Panel UX States (Sprint 12 — Quick Win batch)

NIST SP 800-137 Continuous Monitoring panel. No mock — UX upgrade.

Wires VSPUXState into 2 of 4 loaders:
- loadSchedules() #schedules-body: skeleton + empty + error retry
- loadDeviations() #deviations-body: skeleton + empty + error retry
- loadCadence() unchanged (no table target)
- loadAll() orchestrator unchanged

Defensive: typeof VSPUXState guard with else fallback to original inline HTML.
