# FEAT-15 — Attestation Panel UX States (Sprint 11 — Quick Win batch)

CISA SSDF attestation form panel. No mock data — UX upgrade only.

Wires VSPUXState into 2 loaders:
- loadDraft() #draft-body: skeleton + error retry (was alert popup)
- loadForms() #forms-tbody: skeleton + empty + error retry (was silent + plain HTML)

Sign + download action functions unchanged.

Defensive: typeof VSPUXState guard. alert() kept as else fallback for loadDraft.
